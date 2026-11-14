//go:build linux

package hid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ErrNoCredentials tells the CTAP layer that no credential matched; it is
// returned by CredentialStore implementations and mapped to
// CTAP2_ERR_NO_CREDENTIALS here.
var ErrNoCredentials = errors.New("hid: no credentials for relying party")

// uhidWriter adapts the uhid device to the report sink.
type uhidWriter struct {
	dev interface {
		InjectEvent(data []uint8) error
	}
}

func (w uhidWriter) writeReport(report []byte) error {
	return w.dev.InjectEvent(report)
}

// CBOR CTAP2 request/response shapes. Integer map keys per the CTAP2 spec.
type makeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttStmt  map[string]interface{} `cbor:"3,keyasint"`
}

// GetAssertion response shapes. Entity maps use text keys per the
// DOM-to-CBOR conversion, and structs pin the canonical wire order:
// Go map iteration is randomized (swiss maps shuffle every traversal)
// and fxamacker encodes plain maps in iteration order, so a map
// literal here is a coin flip against Chrome's strict
// monotonic-key validation ("id" encodes to 3 bytes and sorts before
// "type" at 5).
type credentialDescriptor struct {
	ID   []byte `cbor:"id"`   // encoded key 62 6964 — sorts first
	Type string `cbor:"type"` // encoded key 64 74797065
}

type userEntity struct {
	ID []byte `cbor:"id"`
}

type getAssertionResponse struct {
	Credential credentialDescriptor `cbor:"1,keyasint"`
	AuthData   []byte               `cbor:"2,keyasint"`
	Signature  []byte               `cbor:"3,keyasint"`
	User       userEntity           `cbor:"4,keyasint"`
}

// Field order per CTAP 2.0 §5.4 authenticatorGetInfo: options at key 4,
// maxMsgSize at key 5, algorithms at key 10 — the layout Chrome,
// libfido2, and shipped authenticators parse.
// getInfoOptions fields are declared in CBOR canonical key order
// (byte length, then byte-wise): Chrome's CBOR reader rejects maps whose
// keys are not strictly monotonically increasing.
// uv=true means the device performs user verification itself: the gate
// (zdr face via polkit) is that mechanism, and Chrome requires it for
// username-less GetAssertion.
type getInfoOptions struct {
	Rk bool `cbor:"rk"`
	Up bool `cbor:"up"`
	UV bool `cbor:"uv"`
}

// Algorithms (key 10, CTAP 2.1 field) must be present: Chrome 157
// classifies candidate authenticators by this field and refuses a device
// without it as "no common algorithms" before dispatching any request.
// Entity maps use text keys, inner algorithm maps in canonical order
// ("alg" sorts before "type").
type getInfoAlgorithm struct {
	Alg  int64  `cbor:"alg"`
	Type string `cbor:"type"`
}

var getInfoAlgorithms = []getInfoAlgorithm{
	{Alg: -7, Type: "public-key"},
	{Alg: -8, Type: "public-key"},
}

type getInfoResponse struct {
	Versions   []string           `cbor:"1,keyasint"`
	Extensions []string           `cbor:"2,keyasint"`
	AAGUID     []byte             `cbor:"3,keyasint"`
	Options    getInfoOptions     `cbor:"4,keyasint"`
	MaxMsgSize uint               `cbor:"5,keyasint"`
	Algorithms []getInfoAlgorithm `cbor:"10,keyasint"`
}

// decodeRequest parses an inbound CTAP2 request body. fxamacker decodes
// CBOR integer map keys as uint64 when targeting interface{}; keys are
// normalized to int so the accessors below can use CTAP's key numbers.
func decodeRequest(data []byte) (map[interface{}]interface{}, error) {
	var raw map[interface{}]interface{}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return normalizeMap(raw), nil
}

// normalizeMap converts uint64 keys to int, recursively.
func normalizeMap(in map[interface{}]interface{}) map[interface{}]interface{} {
	out := make(map[interface{}]interface{}, len(in))
	for k, v := range in {
		if key, ok := k.(uint64); ok {
			k = int(key)
		}
		switch val := v.(type) {
		case map[interface{}]interface{}:
			v = normalizeMap(val)
		case []interface{}:
			for i := range val {
				if m, ok := val[i].(map[interface{}]interface{}); ok {
					val[i] = normalizeMap(m)
				}
			}
		}
		out[k] = v
	}
	return out
}

// intAt reads an integer value regardless of decode width.
func intAt(m map[interface{}]interface{}, key interface{}) (int64, bool) {
	switch v := m[key].(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case uint64:
		return int64(v), true
	default:
		return 0, false
	}
}

func textAt(m map[interface{}]interface{}, key interface{}) string {
	s, _ := m[key].(string)
	return s
}

func bytesAt(m map[interface{}]interface{}, key interface{}) []byte {
	b, _ := m[key].([]byte)
	return b
}

func boolAt(m map[interface{}]interface{}, key interface{}) bool {
	b, _ := m[key].(bool)
	return b
}

// boolOK reports whether the key is present with a boolean value,
// distinguishing "explicitly false" from "absent".
func boolOK(m map[interface{}]interface{}, key string) (bool, bool) {
	b, ok := m[key].(bool)
	return b, ok
}

// send frames and writes a complete device message.
func (a *Authenticator) send(channelID uint32, command byte, payload []byte) {
	for _, report := range encodeInitReply(channelID, command, payload) {
		if err := a.writer.writeReport(report); err != nil {
			a.log.Warn("hid: failed writing report", "err", err)
			return
		}
	}
}

func (a *Authenticator) sendCBORStatus(channelID uint32, status byte) {
	a.send(channelID, cmdCBOR, []byte{status})
}

func (a *Authenticator) sendError(channelID uint32, code byte) {
	a.send(channelID, cmdError, []byte{code})
}

// waitGate asks the gate for one approval, ticking keepalives at the host
// while the wait is pending. It returns the approval and a classification
// of failure: timeout vs deny.
func (a *Authenticator) waitGate(ctx context.Context, cid uint32, op Operation) (approved bool, timedOut bool) {
	gctx, cancel := context.WithTimeout(ctx, gateTimeout)
	defer cancel()

	approvedCh := make(chan bool, 1)
	go func() { approvedCh <- a.gate.Approve(gctx, op) }()

	ticker := time.NewTicker(keepaliveTick)
	defer ticker.Stop()

	for {
		select {
		case <-gctx.Done():
			if ctx.Err() != nil {
				return false, false // caller canceled; no response anyway
			}
			return false, true
		case ok := <-approvedCh:
			return ok, false
		case <-ticker.C:
			// Still waiting on the gate: report user-presence-needed so
			// the host keeps its dialog in the "touch the device" state.
			a.send(cid, cmdKeepalive, encodeKeepalive(statusUpNeeded))
		}
	}
}

// makeCredential handles CTAP2 authenticatorMakeCredential (0x01).
func (a *Authenticator) makeCredential(ctx context.Context, data []byte, cid uint32) (byte, []byte) {
	req, err := decodeRequest(data)
	if err != nil {
		return statusInvalidCBOR, nil
	}
	rp, _ := req[2].(map[interface{}]interface{})
	user, _ := req[3].(map[interface{}]interface{})
	rpID := textAt(rp, "id")
	rpName := textAt(rp, "name")
	userID := bytesAt(user, "id")
	userName := textAt(user, "name")
	userDisplayName := textAt(user, "displayName")
	if rpID == "" || len(userID) == 0 {
		slog.Warn("hid: MakeCredential rejected as missing parameter",
			"req_len", len(data),
			"req_keys", fmt.Sprintf("%v", req),
			"rpID", rpID,
			"user_id_len", len(userID))
		return statusMissingParam, nil
	}

	// Chromium's FidoDeviceAuthenticator::GetTouch probes devices with a
	// dummy MakeCredential whose RP ID is ".dummy" (its kDummyRpID) to
	// collect a touch. The probe flows through the gate like any
	// registration (the approval IS the touch Chrome counts), and the
	// store answers it ephemerally — Chrome discards the response
	// unconditionally. A real site cannot claim ".dummy": it is not a
	// valid domain.
	if rpID == ".dummy" {
		slog.Info("hid: Chromium touch probe routed through gate", "rpID", rpID)
	}

	// D4: ES256 only on the CTAP surface.
	algOK := false
	params, _ := req[4].([]interface{})
	for _, p := range params {
		pm, _ := p.(map[interface{}]interface{})
		if textAt(pm, "type") == "public-key" {
			if alg, ok := intAt(pm, "alg"); ok && alg == -7 {
				algOK = true
			}
		}
	}
	if !algOK {
		return statusUnsupportedAlgorithm, nil
	}

	// User verification: the gate (zdr face via polkit) is the UV
	// mechanism, so a uv-flagged request runs the gate and sets the UV
	// flag on approval. Options arrive at top-level key 7 as a map with
	// text keys ("rk", "uv", ...); excludeList entries at key 5 are
	// descriptor maps with text keys too.
	options, _ := req[7].(map[interface{}]interface{})
	uvRequested := boolAt(options, "uv")
	if uvRequested {
		slog.Info("hid: MakeCredential requests user verification", "rpID", rpID)
	}

	// Exclude list (key 5): if any listed credential is ours, the site
	// already has this user registered — refuse before prompting so no
	// duplicate credential is created. CTAP2_ERR_CREDENTIAL_EXCLUDED.
	if excludeList, ok := req[5].([]interface{}); ok {
		for _, item := range excludeList {
			desc, _ := item.(map[interface{}]interface{})
			id := bytesAt(desc, "id")
			if len(id) == 0 {
				continue
			}
			excluded, err := a.store.HasCredential(id)
			if err != nil {
				a.log.Error("hid: exclude list lookup failed", "rpID", rpID, "err", err)
				return statusOperationDenied, nil
			}
			if excluded {
				return statusCredentialExcluded, nil
			}
		}
	}

	// shortcut: the gate is invoked with no per-site attribution because
	// polkit actions cannot carry dynamic text; the daemon logs the RPID.
	slog.Info("hid: MakeCredential accepted for gate", "rpID", rpID, "user", userName)
	approved, timedOut := a.waitGate(ctx, cid, Operation{Kind: OperationRegister, RPID: rpID})
	if timedOut {
		return statusUserActionTimeout, nil
	}
	if !approved {
		return statusOperationDenied, nil
	}

	credID, _, coseKey, err := a.store.Create(rpID, rpName, userName, userDisplayName)
	if err != nil {
		a.log.Error("hid: credential creation failed", "rpID", rpID, "err", err)
		return statusOperationDenied, nil
	}

	attested, err := attestedCredentialData(credID, coseKey)
	if err != nil {
		return statusInvalidCBOR, nil
	}
	flags := FlagUP | FlagAT
	if uvRequested {
		flags |= FlagUV // the gate's face verification performed UV
	}
	authData := authenticatorData(rpID, byte(flags), 0, attested)

	resp, err := cbor.Marshal(makeCredentialResponse{
		Fmt:      "none",
		AuthData: authData,
		AttStmt:  map[string]interface{}{},
	})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, resp
}

// getAssertion handles CTAP2 authenticatorGetAssertion (0x02).
func (a *Authenticator) getAssertion(ctx context.Context, data []byte, cid uint32) (byte, []byte) {
	req, err := decodeRequest(data)
	if err != nil {
		return statusInvalidCBOR, nil
	}
	rpID := textAt(req, 1)
	clientDataHash := bytesAt(req, 2)
	if rpID == "" || len(clientDataHash) != 32 {
		return statusMissingParam, nil
	}

	// GetAssertion options live at top-level key 5 ("userPresence"
	// defaults to true; "uv" defaults to false). Chrome's exclude-list
	// silent sign sets userPresence=false: answer without prompting and
	// without the UP flag so the platform learns which credentials exist.
	options, _ := req[5].(map[interface{}]interface{})
	silent := false
	if present, ok := boolOK(options, "userPresence"); ok && !present {
		silent = true
	}
	uvRequested := boolAt(options, "uv") && !silent

	// Consult availability before the gate: a site the user has no
	// credentials for must not trigger a prompt (0x2E without waiting).
	available, err := a.store.HasCredentialsForRPID(rpID)
	if err != nil {
		a.log.Error("hid: credential lookup failed", "rpID", rpID, "err", err)
		return statusOperationDenied, nil
	}
	if !available {
		return statusNoCredentials, nil
	}

	var credentialID []byte
	allowList, _ := req[3].([]interface{})
	for _, item := range allowList {
		im, _ := item.(map[interface{}]interface{})
		if id := bytesAt(im, "id"); len(id) > 0 {
			credentialID = id
			break
		}
	}

	// The gate is the user-presence touch (and, for uv-flagged requests,
	// the face verification). Silent exclude-list signs skip it entirely.
	var approved = true
	if !silent {
		var timedOut bool
		approved, timedOut = a.waitGate(ctx, cid, Operation{Kind: OperationAuthenticate, RPID: rpID})
		if timedOut {
			return statusUserActionTimeout, nil
		}
		if !approved {
			return statusOperationDenied, nil
		}
	}

	usedID, userHandle, authData, signature, err := a.store.Assert(rpID, credentialID, clientDataHash, !silent, uvRequested && !silent)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return statusNoCredentials, nil
		}
		a.log.Warn("hid: assertion refused", "rpID", rpID, "err", err)
		return statusInvalidCredential, nil
	}
	if len(usedID) == 0 {
		return statusInvalidCredential, nil
	}

	// Per CTAP 2.0 §5.2: key 1 is a PublicKeyCredentialDescriptor map
	// (type 1, id 2), key 4 a user entity map (id 1). Raw bytes in
	// either slot make the platform drop the assertion.
	resp, err := cbor.Marshal(getAssertionResponse{
		Credential: credentialDescriptor{ID: usedID, Type: "public-key"},
		AuthData:   authData,
		Signature:  signature,
		User:       userEntity{ID: userHandle},
	})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, resp
}
