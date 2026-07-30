package memory

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

const (
	cursorVersion  = byte(1)
	cursorScopeLen = 16
	cursorMACLen   = sha256.Size
	cursorFixedLen = 1 + 1 + cursorScopeLen + 8 + 8 + 4 + 2 + cursorMACLen
)

type cursorKeySource func([]byte) (int, error)

func initializeCursorKey(destination []byte) (int, error) { return rand.Read(destination) }

func cursorDomainID(domain string) (byte, bool) {
	switch domain {
	case "revision":
		return 1, true
	case "history":
		return 2, true
	case "event":
		return 3, true
	default:
		return 0, false
	}
}

func (s *Store) cursorScope(domain, namespace, slot string) [cursorScopeLen]byte {
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write([]byte("scope\x00"))
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(namespace))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(slot))
	var result [cursorScopeLen]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (s *Store) newCursorLocked(cursor cursorState) (string, error) {
	domainID, ok := cursorDomainID(cursor.domain)
	if !ok || !s.cursorKeyOK || len(cursor.revisionID) > int(^uint16(0)) {
		return "", engineError(policyengine.ErrorInternal)
	}
	switch cursor.domain {
	case "revision":
		if cursor.position != 0 || cursor.revisionPublishedAt.IsZero() || cursor.revisionID == "" {
			return "", engineError(policyengine.ErrorInternal)
		}
	case "history", "event":
		if cursor.position == 0 || !cursor.revisionPublishedAt.IsZero() || cursor.revisionID != "" {
			return "", engineError(policyengine.ErrorInternal)
		}
	}
	payloadLen := cursorFixedLen - cursorMACLen + len(cursor.revisionID)
	if base64.RawURLEncoding.EncodedLen(payloadLen+cursorMACLen) > policyengine.MaxIdentifierBytes {
		return "", engineError(policyengine.ErrorInternal)
	}
	payload := make([]byte, payloadLen, payloadLen+cursorMACLen)
	payload[0] = cursorVersion
	payload[1] = domainID
	scope := s.cursorScope(cursor.domain, cursor.namespace, cursor.slot)
	copy(payload[2:2+cursorScopeLen], scope[:])
	offset := 2 + cursorScopeLen
	binary.BigEndian.PutUint64(payload[offset:offset+8], cursor.position)
	offset += 8
	if cursor.domain == "revision" {
		binary.BigEndian.PutUint64(payload[offset:offset+8], uint64(cursor.revisionPublishedAt.Unix()))
	}
	offset += 8
	if cursor.domain == "revision" {
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(cursor.revisionPublishedAt.Nanosecond()))
	}
	offset += 4
	binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(len(cursor.revisionID)))
	offset += 2
	copy(payload[offset:], cursor.revisionID)
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write(payload)
	token := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (s *Store) cursorStateLocked(value, domain, namespace, slot string) (cursorState, error) {
	if value == "" {
		return cursorState{}, nil
	}
	domainID, ok := cursorDomainID(domain)
	if !ok || !s.cursorKeyOK {
		return cursorState{}, engineError(policyengine.ErrorInternal)
	}
	if len(value) > policyengine.MaxIdentifierBytes {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	token, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(token) < cursorFixedLen {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	payload, suppliedMAC := token[:len(token)-cursorMACLen], token[len(token)-cursorMACLen:]
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(suppliedMAC, mac.Sum(nil)) || payload[0] != cursorVersion || payload[1] != domainID {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	expectedScope := s.cursorScope(domain, namespace, slot)
	if subtle.ConstantTimeCompare(payload[2:2+cursorScopeLen], expectedScope[:]) != 1 {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	offset := 2 + cursorScopeLen
	position := binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	publishedSeconds := int64(binary.BigEndian.Uint64(payload[offset : offset+8]))
	offset += 8
	publishedNanos := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4
	if publishedNanos >= uint32(time.Second) {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	revisionLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if revisionLen != len(payload)-offset {
		return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
	}
	result := cursorState{
		domain: domain, namespace: namespace, slot: slot, position: position,
		revisionID: string(payload[offset:]),
	}
	switch domain {
	case "revision":
		result.revisionPublishedAt = time.Unix(publishedSeconds, int64(publishedNanos)).UTC()
		if position != 0 || revisionLen == 0 || result.revisionPublishedAt.IsZero() {
			return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
		}
	case "history", "event":
		if position == 0 || publishedSeconds != 0 || publishedNanos != 0 || revisionLen != 0 {
			return cursorState{}, engineError(policyengine.ErrorInvalidArgument)
		}
	}
	return result, nil
}

func (s *Store) cursorPositionLocked(value, domain, namespace, slot string) (uint64, error) {
	cursor, err := s.cursorStateLocked(value, domain, namespace, slot)
	return cursor.position, err
}
