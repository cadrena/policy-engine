package sqlite

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

type cursorDomain byte

const (
	cursorDomainRevision cursorDomain = iota + 1
	cursorDomainHistory
	cursorDomainEvent
)

const (
	cursorScopeLength = 16
	cursorMACLength   = sha256.Size
	cursorFixedLength = 1 + 1 + cursorScopeLength + 8 + 8 + 8 + 4 + 2
)

type cursorState struct {
	domain              cursorDomain
	namespace           string
	slot                string
	position            uint64
	boundary            uint64
	revisionPublishedAt time.Time
	revisionID          string
}

func (s *Store) newCursor(value cursorState) (string, error) {
	if !validCursorState(value) {
		return "", sqliteError(policyengine.ErrorInternal)
	}
	seconds, nanos, ok := cursorCodecTime(value)
	if !ok {
		return "", sqliteError(policyengine.ErrorInternal)
	}
	if len(value.revisionID) > policyengine.MaxIdentifierBytes || len(value.revisionID) > int(^uint16(0)) {
		return "", sqliteError(policyengine.ErrorInternal)
	}
	bodyLength := cursorFixedLength + len(value.revisionID)
	if base64.RawURLEncoding.EncodedLen(bodyLength+cursorMACLength) > policyengine.MaxIdentifierBytes {
		return "", sqliteError(policyengine.ErrorInternal)
	}
	body := make([]byte, 0, bodyLength)
	body = append(body, codecVersion, byte(value.domain))
	scope := s.cursorScope(value.domain, value.namespace, value.slot)
	body = append(body, scope[:]...)
	body = appendCodecUint64(body, value.position)
	body = appendCodecUint64(body, value.boundary)
	body = appendCodecUint64(body, uint64(seconds))
	body = appendCodecUint32(body, nanos)
	body = appendCodecUint16(body, uint16(len(value.revisionID)))
	body = append(body, value.revisionID...)
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write(body)
	token := append(body, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *Store) decodeCursor(value string, domain cursorDomain, namespace, slot string) (cursorState, error) {
	if value == "" {
		return cursorState{domain: domain, namespace: namespace, slot: slot}, nil
	}
	if !validCursorScope(domain, namespace, slot) || len(value) > policyengine.MaxIdentifierBytes {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	token, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(token) < cursorFixedLength+cursorMACLength {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	if base64.RawURLEncoding.EncodeToString(token) != value {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	body, suppliedMAC := token[:len(token)-cursorMACLength], token[len(token)-cursorMACLength:]
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write(body)
	if !hmac.Equal(suppliedMAC, mac.Sum(nil)) {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	reader := codecReader{data: body}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	actualDomain, ok := reader.byte()
	if !ok || cursorDomain(actualDomain) != domain {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	suppliedScope, ok := reader.fixed(cursorScopeLength)
	if !ok {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	expectedScope := s.cursorScope(domain, namespace, slot)
	if subtle.ConstantTimeCompare(suppliedScope, expectedScope[:]) != 1 {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	position, ok := reader.uint64()
	if !ok {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	boundary, ok := reader.uint64()
	if !ok {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	seconds, ok := reader.int64()
	if !ok {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	nanos, ok := reader.uint32()
	if !ok {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	revisionID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok || !reader.done() {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	result := cursorState{
		domain: domain, namespace: namespace, slot: slot, position: position, boundary: boundary, revisionID: revisionID,
	}
	if domain == cursorDomainRevision {
		when, valid := decodeCodecTime(seconds, nanos)
		if !valid {
			return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
		}
		result.revisionPublishedAt = when
	} else if seconds != 0 || nanos != 0 {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	if !validCursorState(result) {
		return cursorState{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	return result, nil
}

func (s *Store) cursorScope(domain cursorDomain, namespace, slot string) [cursorScopeLength]byte {
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write([]byte("cadrena.cursor.scope\x00"))
	_, _ = mac.Write([]byte{byte(domain), 0})
	_, _ = mac.Write([]byte(namespace))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(slot))
	var result [cursorScopeLength]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func validCursorScope(domain cursorDomain, namespace, slot string) bool {
	if namespace == "" {
		return false
	}
	switch domain {
	case cursorDomainRevision, cursorDomainEvent:
		return slot == ""
	case cursorDomainHistory:
		return slot != ""
	default:
		return false
	}
}

func validCursorState(value cursorState) bool {
	if !validCursorScope(value.domain, value.namespace, value.slot) {
		return false
	}
	switch value.domain {
	case cursorDomainRevision:
		if value.position != 0 || value.boundary != 0 || value.revisionPublishedAt.IsZero() || value.revisionID == "" {
			return false
		}
		_, err := policyengine.ParseRevisionID(value.revisionID)
		return err == nil
	case cursorDomainHistory:
		return value.position > 0 && value.boundary < value.position && value.revisionPublishedAt.IsZero() && value.revisionID == ""
	case cursorDomainEvent:
		return value.position > 0 && value.boundary < value.position && value.revisionPublishedAt.IsZero() && value.revisionID == ""
	default:
		return false
	}
}

func cursorCodecTime(value cursorState) (int64, uint32, bool) {
	if value.domain != cursorDomainRevision {
		return 0, 0, true
	}
	return codecTime(value.revisionPublishedAt)
}

func (r *codecReader) fixed(length int) ([]byte, bool) {
	if length < 0 || length > len(r.data)-r.offset {
		return nil, false
	}
	value := r.data[r.offset : r.offset+length]
	r.offset += length
	return value, true
}
