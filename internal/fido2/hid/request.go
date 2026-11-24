//go:build linux

package hid

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// Modes are immutable and shared. The decoder enforces C20 §6's recommended
// strict input policy; the encoder independently enforces its mandatory output
// rules. Unknown fields are still ignored after their wire encoding is checked.
var ctapDecoder = func() cbor.DecMode {
	mode, err := (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		BigIntDec:        cbor.BigIntDecodePointer,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  4,
		MaxArrayElements: 1024,
		MaxMapPairs:      1024,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

var ctapEncoder = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

var errUnexpectedType = errors.New("hid: unexpected CBOR type")

// decodeRequest checks the complete single CBOR object before accessing fields.
// Large negative integers use comparable *big.Int keys. Canonical wire ordering
// rejects duplicate primitive keys independently of Go key equality.
func decodeRequest(data []byte) (map[any]any, error) {
	var raw any
	if err := ctapDecoder.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if _, err := parseCanonicalItem(data); err != nil {
		return nil, err
	}
	req, ok := raw.(map[any]any)
	if !ok {
		return nil, errUnexpectedType
	}
	return normalizeMap(req), nil
}

// parseCanonicalItem checks minimal headers and map ordering on already
// well-formed, definite, tag-free CBOR. Unlike decode/re-encode comparison this
// preserves floating-point widths and bit patterns, as C20 §6 requires.
func parseCanonicalItem(data []byte) (int, error) {
	major, ai := data[0]>>5, data[0]&31
	n, value := 1, uint64(ai)
	if ai >= 24 {
		width := 1 << (ai - 24)
		n += width
		value = 0
		for _, b := range data[1:n] {
			value = value<<8 | uint64(b)
		}
		if major != 7 && ((ai == 24 && value < 24) || (ai == 25 && value <= math.MaxUint8) || (ai == 26 && value <= math.MaxUint16) || (ai == 27 && value <= math.MaxUint32)) {
			return 0, fmt.Errorf("hid: nonminimal CBOR header")
		}
	}
	switch major {
	case 2, 3:
		n += int(value)
	case 4, 5:
		var previous []byte
		for range value {
			if major == 5 {
				start := n
				keyMajor := data[n] >> 5
				if keyMajor >= 4 && keyMajor <= 6 {
					return 0, fmt.Errorf("hid: complex CBOR map key")
				}
				size, err := parseCanonicalItem(data[n:])
				if err != nil {
					return 0, err
				}
				n += size
				key := data[start:n]
				if previous != nil && bytes.Compare(previous, key) >= 0 {
					return 0, fmt.Errorf("hid: unordered CBOR map keys")
				}
				previous = key
			}
			size, err := parseCanonicalItem(data[n:])
			if err != nil {
				return 0, err
			}
			n += size
		}
	}
	return n, nil
}

func requestError(err error) byte {
	if errors.Is(err, errUnexpectedType) {
		return statusUnexpectedType
	}
	return statusInvalidCBOR
}

// requestFields is a pure parser for the shared command field rules. Semantic
// option/PIN errors are handled later in the order specified by §§5.1–5.2.
type requestFields map[any]any

func (r requestFields) required(key any) (any, byte) {
	v, ok := r[key]
	if !ok {
		return nil, statusMissingParam
	}
	return v, statusOK
}
func (r requestFields) hash(key int) ([]byte, byte) {
	v, status := r.required(key)
	if status != statusOK {
		return nil, status
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, statusUnexpectedType
	}
	if len(b) != 32 {
		return nil, statusInvalidLength
	}
	return b, statusOK
}
func (r requestFields) text(key any) (string, byte) {
	v, status := r.required(key)
	if status != statusOK {
		return "", status
	}
	s, ok := v.(string)
	if !ok {
		return "", statusUnexpectedType
	}
	if s == "" {
		return "", statusInvalidParameter
	}
	return s, statusOK
}
func (r requestFields) entity(key int, textFields ...string) (requestFields, byte) {
	v, status := r.required(key)
	if status != statusOK {
		return nil, status
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, statusUnexpectedType
	}
	for _, name := range textFields {
		if value, present := m[name]; present {
			if _, ok := value.(string); !ok {
				return nil, statusUnexpectedType
			}
		}
	}
	return requestFields(m), statusOK
}
func (r requestFields) options(key int) (requestFields, byte) {
	v, present := r[key]
	if !present {
		return requestFields{}, statusOK
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, statusUnexpectedType
	}
	for _, name := range []string{"rk", "up", "uv"} {
		if value, present := m[name]; present {
			if _, ok := value.(bool); !ok {
				return nil, statusUnexpectedType
			}
		}
	}
	return requestFields(m), statusOK
}
func (r requestFields) extensions(key int) byte {
	if v, present := r[key]; present {
		if _, ok := v.(map[any]any); !ok {
			return statusUnexpectedType
		}
	}
	return statusOK
}
func (r requestFields) pinTypes(authKey, protocolKey int) byte {
	if v, present := r[authKey]; present {
		b, ok := v.([]byte)
		if !ok {
			return statusUnexpectedType
		}
		if len(b) != 0 && len(b) != 16 {
			return statusInvalidLength
		}
	}
	if v, present := r[protocolKey]; present {
		if _, ok := v.(uint64); !ok {
			return statusUnexpectedType
		}
	}
	return statusOK
}
func (r requestFields) pinStatus(authKey, protocolKey int) byte {
	auth, hasAuth := r[authKey]
	_, hasProtocol := r[protocolKey]
	if !hasAuth && !hasProtocol {
		return statusOK
	}
	// C20 §§5.5.8.1–2 give empty pinAuth a touch-selection meaning,
	// independent of a usable PIN token or protocol. It cannot sign.
	if hasAuth && len(auth.([]byte)) == 0 {
		return statusPINNotSet
	}
	if !hasAuth || !hasProtocol {
		return statusMissingParam
	}
	// No client PIN/token is supported, including protocol 1. Never ignore
	// authentication parameters and proceed with a weaker signature.
	return statusPINAuthInvalid
}
func (r requestFields) algorithm() (bool, byte) {
	v, status := r.required(4)
	if status != statusOK {
		return false, status
	}
	params, ok := v.([]any)
	if !ok {
		return false, statusUnexpectedType
	}
	supported := false
	for _, p := range params {
		m, ok := p.(map[any]any)
		if !ok {
			return false, statusUnexpectedType
		}
		fields := requestFields(m)
		rawKind, status := fields.required("type")
		if status != statusOK {
			return false, status
		}
		kind, ok := rawKind.(string)
		if !ok {
			return false, statusUnexpectedType
		}
		if _, status := fields.required("alg"); status != statusOK {
			return false, status
		}
		switch alg := m["alg"].(type) {
		case int64:
			supported = supported || (kind == "public-key" && alg == -7)
		case uint64:
			// Positive algorithm identifiers are well-typed but unsupported.
		default:
			return false, statusUnexpectedType
		}
	}
	return supported, statusOK
}

// consent exposes actual checks only after a complete, sufficient approval.
func (a *Authenticator) consent(ctx context.Context, cid uint32, op Operation) (Approval, byte) {
	approval, _ := a.waitGate(ctx, cid, op)
	if !approval.Approved {
		return Approval{}, statusOperationDenied
	}
	return approval, statusOK
}
