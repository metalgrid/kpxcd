//go:build linux

package hid

import (
	"context"
	"slices"
	"time"
)

const cmdGetNextAssertion byte = 0x08
const statusNotAllowed byte = 0x30

// pendingAssertions holds identifiers and the original authorization only.
// a.mu protects both the pointer and its cursor/timer. The pointer itself is
// also a generation token: obsolete work cannot restore cleared authorization.
type pendingAssertions struct {
	cid         uint32
	refs        []CredentialReference
	hash        []byte
	approval    Approval
	next        int
	lastSuccess time.Time
}

func (a *Authenticator) rememberAssertions(ctx context.Context, state *pendingAssertions) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped || ctx.Err() != nil {
		return
	}
	if op, ok := ctx.Value(operationKey{}).(*inflightOp); ok && a.owner != op {
		return
	}
	state.hash = slices.Clone(state.hash)
	a.pending = state
}

func (a *Authenticator) encodeResident(result ResidentAssertion, count int, uv bool) (byte, []byte) {
	if len(result.CredentialID) == 0 || len(result.UserHandle) == 0 {
		return statusInvalidCredential, nil
	}
	user := userEntity{ID: result.UserHandle}
	// Enforce privacy here even when a store supplies unverified names.
	if uv {
		user.Name, user.DisplayName = result.Name, result.DisplayName
	}
	response, err := ctapEncoder.Marshal(getAssertionResponse{Credential: credentialDescriptor{ID: result.CredentialID, Type: "public-key"}, AuthData: result.AuthData, Signature: result.Signature, User: user, NumberOfCredentials: count})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, response
}

func (a *Authenticator) getNextAssertion(ctx context.Context, data []byte, cid uint32) (byte, []byte) {
	a.mu.Lock()
	state := a.pending
	if len(data) != 0 {
		a.pending = nil
		a.mu.Unlock()
		return statusInvalidLength, nil
	}
	if state == nil || state.cid != cid || state.next >= len(state.refs) || time.Since(state.lastSuccess) > 30*time.Second {
		a.pending = nil
		a.mu.Unlock()
		return statusNotAllowed, nil
	}
	index := state.next
	a.mu.Unlock()
	// The store validates the full original set and signs under one boundary.
	if ctx.Err() != nil {
		return statusKeepaliveCancel, nil
	}
	result, err := a.store.AssertResident(state.refs[index], state.refs, state.hash, state.approval.UserPresence, state.approval.UserVerification)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != state || ctx.Err() != nil || a.stopped {
		return statusNotAllowed, nil
	}
	if op, ok := ctx.Value(operationKey{}).(*inflightOp); ok && a.owner != op {
		return statusNotAllowed, nil
	}
	if err != nil {
		a.pending = nil
		return statusNotAllowed, nil
	}
	status, response := a.encodeResident(result, 0, state.approval.UserVerification)
	if status != statusOK {
		a.pending = nil
		return status, nil
	}
	state.next++
	state.lastSuccess = time.Now()
	if state.next == len(state.refs) {
		a.pending = nil
	}
	return status, response
}
