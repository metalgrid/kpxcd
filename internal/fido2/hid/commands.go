//go:build linux

package hid

import (
	"context"
	"errors"
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

type getAssertionResponse struct {
	CredentialID []byte `cbor:"1,keyasint"`
	AuthData     []byte `cbor:"2,keyasint"`
	Signature    []byte `cbor:"3,keyasint"`
	UserID       []byte `cbor:"4,keyasint"`
}

type getInfoResponse struct {
	Versions   []string        `cbor:"1,keyasint"`
	Extensions []string        `cbor:"2,keyasint"`
	AAGUID     []byte          `cbor:"3,keyasint"`
	Options    map[string]bool `cbor:"5,keyasint"`
	MaxMsgSize uint            `cbor:"6,keyasint"`
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
func intAt(m map[interface{}]interface{}, key int) (int64, bool) {
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

func textAt(m map[interface{}]interface{}, key int) string {
	s, _ := m[key].(string)
	return s
}

func bytesAt(m map[interface{}]interface{}, key int) []byte {
	b, _ := m[key].([]byte)
	return b
}

func boolAt(m map[interface{}]interface{}, key int) bool {
	b, _ := m[key].(bool)
	return b
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
			a.send(cid, cmdKeepalive, encodeKeepalive(statusProcessing))
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
	rpID := textAt(rp, 1)
	rpName := textAt(rp, 2)
	userID := bytesAt(user, 1)
	userName := textAt(user, 2)
	userDisplayName := textAt(user, 3)
	if rpID == "" || len(userID) == 0 {
		return statusMissingParam, nil
	}

	// D4: ES256 only on the CTAP surface.
	algOK := false
	params, _ := req[4].([]interface{})
	for _, p := range params {
		pm, _ := p.(map[interface{}]interface{})
		if alg, ok := intAt(pm, 1); ok && alg == -7 {
			algOK = true
		}
	}
	if !algOK {
		return statusUnsupportedAlgorithm, nil
	}

	// D4: no user verification mechanism exists; a UV-required request is
	// denied rather than silently downgraded.
	if boolAt(req, 7) {
		return statusOperationDenied, nil
	}

	// shortcut: the gate is invoked with no per-site attribution because
	// polkit actions cannot carry dynamic text; the daemon logs the RPID.
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
	authData := authenticatorData(rpID, FlagUP|FlagAT, 0, attested)

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

	// D4: no user verification mechanism exists.
	if boolAt(req, 7) {
		return statusOperationDenied, nil
	}

	// Consult availability before the gate: a site the user has no
	// credentials for must not trigger a prompt (0x22 without waiting).
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
		if id := bytesAt(im, 2); len(id) > 0 {
			credentialID = id
			break
		}
	}

	approved, timedOut := a.waitGate(ctx, cid, Operation{Kind: OperationAuthenticate, RPID: rpID})
	if timedOut {
		return statusUserActionTimeout, nil
	}
	if !approved {
		return statusOperationDenied, nil
	}

	usedID, userHandle, authData, signature, err := a.store.Assert(rpID, credentialID, clientDataHash, false)
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

	resp, err := cbor.Marshal(getAssertionResponse{
		CredentialID: usedID,
		AuthData:     authData,
		Signature:    signature,
		UserID:       userHandle,
	})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, resp
}
