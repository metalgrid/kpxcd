//go:build linux

package hid

import (
	"context"
	"errors"
	"time"
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

// C20 §§5.2, 6.2 require entity maps with text keys. All responses use
// the CTAP canonical encoder independently of Go map iteration order.
type credentialDescriptor struct {
	ID   []byte `cbor:"id"`   // encoded key 62 6964 — sorts first
	Type string `cbor:"type"` // encoded key 64 74797065
}

type userEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

type getAssertionResponse struct {
	Credential          credentialDescriptor `cbor:"1,keyasint"`
	AuthData            []byte               `cbor:"2,keyasint"`
	Signature           []byte               `cbor:"3,keyasint"`
	User                userEntity           `cbor:"4,keyasint"`
	NumberOfCredentials int                  `cbor:"5,keyasint,omitempty"`
}

// Field order per CTAP 2.0 §5.4 authenticatorGetInfo: options at key 4,
// maxMsgSize at key 5, algorithms at key 10 — the layout Chrome,
// libfido2, and shipped authenticators parse.
// getInfoOptions fields are declared in CBOR canonical key order
// (byte length, then byte-wise): Chrome's CBOR reader rejects maps whose
// keys are not strictly monotonically increasing.
// uv=true advertises user verification through the polkit gate.
// Chrome requires it for username-less GetAssertion.
// The system authentication configuration determines the method.
type getInfoOptions struct {
	Rk bool `cbor:"rk"`
	Up bool `cbor:"up"`
	UV bool `cbor:"uv"`
}

// C21 §6.4 defines this optional field as credential-generation algorithms,
// not the algorithms of every key the signing/import service can handle.
type getInfoAlgorithm struct {
	Alg  int64  `cbor:"alg"`
	Type string `cbor:"type"`
}

var getInfoAlgorithms = []getInfoAlgorithm{
	{Alg: -7, Type: "public-key"},
}

type getInfoResponse struct {
	Versions   []string           `cbor:"1,keyasint"`
	Extensions []string           `cbor:"2,keyasint"`
	AAGUID     []byte             `cbor:"3,keyasint"`
	Options    getInfoOptions     `cbor:"4,keyasint"`
	MaxMsgSize uint               `cbor:"5,keyasint"`
	Algorithms []getInfoAlgorithm `cbor:"10,keyasint"`
}

// normalizeMap converts uint64 keys to int, recursively.
func normalizeMap(in map[interface{}]interface{}) map[interface{}]interface{} {
	out := make(map[interface{}]interface{}, len(in))
	for k, v := range in {
		if key, ok := k.(uint64); ok && key <= uint64(^uint(0)>>1) {
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

// parseCredentialDescriptors validates restrictions before any credential lookup.
// Unknown text credential types are extension points, not public-key aliases.
func parseCredentialDescriptors(req map[interface{}]interface{}, key int) ([]credentialDescriptor, byte) {
	raw, present := req[key]
	if !present {
		return nil, statusOK
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, 0x11 // CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
	}
	descriptors := make([]credentialDescriptor, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[interface{}]interface{})
		if !ok {
			return nil, 0x11
		}
		if _, present := m["type"]; !present {
			return nil, statusMissingParam
		}
		if _, present := m["id"]; !present {
			return nil, statusMissingParam
		}
		kind, typeOK := m["type"].(string)
		id, idOK := m["id"].([]byte)
		if !typeOK || !idOK {
			return nil, 0x11
		}
		if len(id) == 0 {
			return nil, statusInvalidLength
		}
		if transports, present := m["transports"]; present {
			items, ok := transports.([]any)
			if !ok {
				return nil, statusUnexpectedType
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return nil, statusUnexpectedType
				}
			}
		}
		descriptors = append(descriptors, credentialDescriptor{ID: id, Type: kind})
	}
	return descriptors, statusOK
}

func textAt(m map[interface{}]interface{}, key interface{}) string {
	s, _ := m[key].(string)
	return s
}

// sendError queues the response to a rejected request without blocking reception.
func (a *Authenticator) sendError(channelID uint32, code byte) {
	a.queueOutput(outboundMessage{cid: channelID, command: cmdError, payload: []byte{code}})
}

// waitGate asks the gate for one approval, ticking keepalives at the host
// while the wait is pending. It returns the approval and a classification
// of failure: timeout vs deny.
func (a *Authenticator) waitGate(ctx context.Context, cid uint32, op Operation) (approval Approval, timedOut bool) {
	if ctx.Err() != nil {
		return Approval{}, false
	}
	gctx, cancel := context.WithTimeout(ctx, gateTimeout)
	defer cancel()

	approvedCh := make(chan Approval, 1)
	go func() { approvedCh <- a.gate.Approve(gctx, op) }()

	ticker := time.NewTicker(keepaliveTick)
	defer ticker.Stop()

	for {
		select {
		case <-gctx.Done():
			if ctx.Err() != nil {
				return Approval{}, false // caller canceled; no response anyway
			}
			return Approval{}, true
		case result := <-approvedCh:
			if gctx.Err() != nil || !result.Approved || (op.UserPresence && !result.UserPresence) || (op.UserVerification && !result.UserVerification) {
				return Approval{}, false
			}
			return result, false
		case <-ticker.C:
			// Still waiting on the gate: report user-presence-needed so
			// the host keeps its dialog in the "touch the device" state.
			if current, ok := ctx.Value(operationKey{}).(*inflightOp); ok {
				a.keepalive(current)
			}
		}
	}
}

// keepalive is generation-bound and coalesced if the sink is stalled.
func (a *Authenticator) keepalive(op *inflightOp) {
	a.queueOutput(outboundMessage{op: op, cid: op.cid, command: cmdKeepalive, payload: encodeKeepalive(statusUpNeeded)})
}

// makeCredential handles CTAP2 authenticatorMakeCredential (0x01).
func (a *Authenticator) makeCredential(ctx context.Context, data []byte, cid uint32) (byte, []byte) {
	req, err := decodeRequest(data)
	if err != nil {
		return requestError(err), nil
	}
	fields := requestFields(req)
	if _, status := fields.hash(1); status != statusOK {
		return status, nil
	}
	rp, status := fields.entity(2, "name", "icon")
	if status != statusOK {
		return status, nil
	}
	rpID, status := rp.text("id")
	if status != statusOK {
		return status, nil
	}
	user, status := fields.entity(3, "name", "displayName", "icon")
	if status != statusOK {
		return status, nil
	}
	rawID, status := user.required("id")
	if status != statusOK {
		return status, nil
	}
	userID, ok := rawID.([]byte)
	if !ok {
		return statusUnexpectedType, nil
	}
	if len(userID) < 1 || len(userID) > 64 {
		return statusInvalidLength, nil
	}
	algOK, status := fields.algorithm()
	if status != statusOK {
		return status, nil
	}
	excludeList, status := parseCredentialDescriptors(req, 5)
	if status != statusOK {
		return status, nil
	}
	if status := fields.extensions(6); status != statusOK {
		return status, nil
	}
	options, status := fields.options(7)
	if status != statusOK {
		return status, nil
	}
	if status := fields.pinTypes(8, 9); status != statusOK {
		return status, nil
	}
	uvRequested, _ := options["uv"].(bool)
	op := Operation{Kind: OperationRegister, RPID: rpID, UserPresence: true, UserVerification: uvRequested}

	// C20 §5.1 processes an exclusion before algorithm/options/authentication
	// errors, but never discloses a match without successful user presence.
	for _, desc := range excludeList {
		if desc.Type != "public-key" {
			continue
		}
		excluded, err := a.store.HasCredential(rpID, desc.ID)
		if err != nil {
			return statusOperationDenied, nil
		}
		if excluded {
			op.UserVerification = false
			if _, status := a.consent(ctx, cid, op); status != statusOK {
				return status, nil
			}
			return statusCredentialExcluded, nil
		}
	}
	if !algOK {
		return statusUnsupportedAlgorithm, nil
	}
	if _, present := options["up"]; present {
		return statusInvalidOption, nil
	}
	if status := fields.pinStatus(8, 9); status != statusOK {
		if status == statusPINNotSet {
			op.UserVerification = false
			if _, denied := a.consent(ctx, cid, op); denied != statusOK {
				return denied, nil
			}
		}
		return status, nil
	}
	approval, status := a.consent(ctx, cid, op)
	if status != statusOK {
		return status, nil
	}
	rpName := textAt(rp, "name")
	userName := textAt(user, "name")
	userDisplayName := textAt(user, "displayName")

	if ctx.Err() != nil {
		return statusKeepaliveCancel, nil
	}
	credID, _, coseKey, err := a.store.Create(rpID, rpName, userName, userDisplayName, userID, options["rk"] == true)
	if err != nil {
		a.log.Error("hid: credential creation failed")
		return statusOperationDenied, nil
	}

	attested, err := attestedCredentialData(credID, coseKey)
	if err != nil {
		return statusInvalidCBOR, nil
	}
	flags := FlagAT
	if approval.UserPresence {
		flags |= FlagUP
	}
	if approval.UserVerification {
		flags |= FlagUV
	}
	authData := authenticatorData(rpID, byte(flags), 0, attested)

	resp, err := ctapEncoder.Marshal(makeCredentialResponse{
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
		return requestError(err), nil
	}
	fields := requestFields(req)
	rpID, status := fields.text(1)
	if status != statusOK {
		return status, nil
	}
	clientDataHash, status := fields.hash(2)
	if status != statusOK {
		return status, nil
	}
	allowList, status := parseCredentialDescriptors(req, 3)
	if status != statusOK {
		return status, nil
	}
	if status := fields.extensions(4); status != statusOK {
		return status, nil
	}
	options, status := fields.options(5)
	if status != statusOK {
		return status, nil
	}
	if status := fields.pinTypes(6, 7); status != statusOK {
		return status, nil
	}

	// Lookup is read-only. Existence is disclosed only after required consent.
	available, err := a.store.HasCredentialsForRPID(rpID)
	if err != nil {
		return statusOperationDenied, nil
	}
	var credentialID []byte
	for _, desc := range allowList {
		if desc.Type != "public-key" {
			continue
		}
		matches, err := a.store.HasCredential(rpID, desc.ID)
		if err != nil {
			return statusOperationDenied, nil
		}
		if matches {
			credentialID = desc.ID
			break
		}
	}
	upRequested := true
	if up, present := options["up"].(bool); present {
		upRequested = up
	}
	uvRequested, _ := options["uv"].(bool)
	op := Operation{Kind: OperationAuthenticate, RPID: rpID, UserPresence: upRequested, UserVerification: uvRequested}
	if status := fields.pinStatus(6, 7); status != statusOK {
		if status == statusPINNotSet {
			op.UserPresence, op.UserVerification = true, false
			if _, denied := a.consent(ctx, cid, op); denied != statusOK {
				return denied, nil
			}
		}
		return status, nil
	}
	if _, present := options["rk"]; present {
		return statusInvalidOption, nil
	}
	var approval Approval
	if upRequested || uvRequested {
		approval, status = a.consent(ctx, cid, op)
		if status != statusOK {
			return status, nil
		}
	}
	if !available || (len(allowList) > 0 && credentialID == nil) {
		return statusNoCredentials, nil
	}

	if ctx.Err() != nil {
		return statusKeepaliveCancel, nil
	}
	if len(allowList) == 0 {
		refs, err := a.store.ResidentCredentials(rpID)
		if err != nil {
			return statusOperationDenied, nil
		}
		if len(refs) == 0 {
			return statusNoCredentials, nil
		}
		result, err := a.store.AssertResident(refs[0], refs, clientDataHash, approval.UserPresence, approval.UserVerification)
		if err != nil {
			return statusInvalidCredential, nil
		}
		count := 0
		if len(refs) > 1 {
			count = len(refs)
		}
		status, response := a.encodeResident(result, count, approval.UserVerification)
		if status == statusOK && len(refs) > 1 {
			a.rememberAssertions(ctx, &pendingAssertions{cid: cid, refs: refs, hash: clientDataHash, approval: approval, next: 1, lastSuccess: time.Now()})
		}
		return status, response
	}
	usedID, userHandle, authData, signature, err := a.store.Assert(rpID, credentialID, clientDataHash, approval.UserPresence, approval.UserVerification)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return statusNoCredentials, nil
		}
		a.log.Warn("hid: assertion refused")
		return statusInvalidCredential, nil
	}
	if len(usedID) == 0 {
		return statusInvalidCredential, nil
	}

	// C20 §§5.2, 6.2: descriptor and user entity members have text keys.
	// Only the opaque user ID is returned; names require verification and
	// account-selection semantics, which are handled separately.
	resp, err := ctapEncoder.Marshal(getAssertionResponse{
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
