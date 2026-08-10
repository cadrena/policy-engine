package sqlite

import (
	"encoding/binary"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

const codecVersion byte = 1

const (
	provenanceAbsent  byte = 0
	provenancePresent byte = 1
)

// encodeRevisionProvenance produces the version-1 canonical durable form. A
// zero provenance is represented explicitly so a revision without source
// provenance remains distinguishable from a corrupt record.
func encodeRevisionProvenance(value store.RevisionProvenance) ([]byte, error) {
	if value.Valid() {
		sourceName := value.SourceName()
		source := value.OriginalSource()
		if len(sourceName) > policyengine.MaxSourceNameBytes || len(source) > policyengine.MaxPolicySourceBytes {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		encoded := make([]byte, 0, 1+1+2+len(sourceName)+4+len(source))
		encoded = append(encoded, codecVersion, provenancePresent)
		encoded = appendCodecUint16(encoded, uint16(len(sourceName)))
		encoded = append(encoded, sourceName...)
		encoded = appendCodecUint32(encoded, uint32(len(source)))
		encoded = append(encoded, source...)
		return encoded, nil
	}
	if value.SourceName() == "" && len(value.OriginalSource()) == 0 {
		return []byte{codecVersion, provenanceAbsent}, nil
	}
	return nil, sqliteError(policyengine.ErrorIntegrity)
}

func decodeRevisionProvenance(namespace string, encoded []byte) (store.RevisionProvenance, error) {
	reader := codecReader{data: encoded}
	if version, ok := reader.byte(); !ok || version != codecVersion {
		return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
	}
	presence, ok := reader.byte()
	if !ok {
		return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
	}
	switch presence {
	case provenanceAbsent:
		if !reader.done() {
			return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return store.RevisionProvenance{}, nil
	case provenancePresent:
		sourceName, ok := reader.string16(policyengine.MaxSourceNameBytes)
		if !ok {
			return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
		}
		source, ok := reader.bytes32(policyengine.MaxPolicySourceBytes)
		if !ok || !reader.done() {
			return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
		}
		request, err := policyengine.NewPublishRequest(namespace, sourceName, source)
		if err != nil {
			return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
		}
		result, err := store.NewRevisionProvenance(request)
		if err != nil {
			return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return result, nil
	default:
		return store.RevisionProvenance{}, sqliteError(policyengine.ErrorIntegrity)
	}
}

func encodeRevisionMetadata(value policyengine.RevisionMetadata) ([]byte, error) {
	canonical, err := canonicalRevisionMetadata(value)
	if err != nil {
		return nil, err
	}
	seconds, nanos, ok := codecTime(canonical.PublishedAt())
	if !ok {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := make([]byte, 0, 1+2+len(canonical.Namespace())+2+len(canonical.ID())+8+4)
	encoded = append(encoded, codecVersion)
	encoded = appendCodecString16(encoded, canonical.Namespace())
	encoded = appendCodecString16(encoded, canonical.ID())
	encoded = appendCodecUint64(encoded, uint64(seconds))
	encoded = appendCodecUint32(encoded, nanos)
	return encoded, nil
}

func decodeRevisionMetadata(encoded []byte) (policyengine.RevisionMetadata, error) {
	reader := codecReader{data: encoded}
	if version, ok := reader.byte(); !ok || version != codecVersion {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	namespace, ok := reader.string16(policyengine.MaxNamespaceBytes)
	if !ok {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	revisionID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	seconds, ok := reader.int64()
	if !ok {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	nanos, ok := reader.uint32()
	if !ok || !reader.done() {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	when, ok := decodeCodecTime(seconds, nanos)
	if !ok {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	id, err := policyengine.ParseRevisionID(revisionID)
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewRevisionMetadata(namespace, id, when)
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func canonicalRevisionMetadata(value policyengine.RevisionMetadata) (policyengine.RevisionMetadata, error) {
	id, err := policyengine.ParseRevisionID(value.ID())
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewRevisionMetadata(value.Namespace(), id, value.PublishedAt().UTC())
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func encodeActivation(value policyengine.Activation) ([]byte, error) {
	canonical, err := canonicalActivation(value)
	if err != nil {
		return nil, err
	}
	seconds, nanos, ok := codecTime(canonical.ActivatedAt())
	if !ok {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := make([]byte, 0, 1+2+len(canonical.Namespace())+2+len(canonical.Slot())+2+len(canonical.RevisionID())+8+8+4)
	encoded = append(encoded, codecVersion)
	encoded = appendCodecString16(encoded, canonical.Namespace())
	encoded = appendCodecString16(encoded, canonical.Slot())
	encoded = appendCodecString16(encoded, canonical.RevisionID())
	encoded = appendCodecUint64(encoded, canonical.Generation())
	encoded = appendCodecUint64(encoded, uint64(seconds))
	encoded = appendCodecUint32(encoded, nanos)
	return encoded, nil
}

func decodeActivation(encoded []byte) (policyengine.Activation, error) {
	reader := codecReader{data: encoded}
	if version, ok := reader.byte(); !ok || version != codecVersion {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	namespace, ok := reader.string16(policyengine.MaxNamespaceBytes)
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	slot, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	revisionID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	generation, ok := reader.uint64()
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	seconds, ok := reader.int64()
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	nanos, ok := reader.uint32()
	if !ok || !reader.done() {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	when, ok := decodeCodecTime(seconds, nanos)
	if !ok {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewActivation(namespace, slot, revisionID, generation, when)
	if err != nil {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func canonicalActivation(value policyengine.Activation) (policyengine.Activation, error) {
	result, err := policyengine.NewActivation(
		value.Namespace(), value.Slot(), value.RevisionID(), value.Generation(), value.ActivatedAt().UTC(),
	)
	if err != nil {
		return policyengine.Activation{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func encodeStateEvent(value policyengine.StateEvent) ([]byte, error) {
	canonical, err := canonicalStateEvent(value)
	if err != nil {
		return nil, err
	}
	seconds, nanos, ok := codecTime(canonical.OccurredAt())
	if !ok {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := make([]byte, 0, 1+1+2+len(canonical.Namespace())+2+len(canonical.Cursor())+2+len(canonical.RevisionID())+2+len(canonical.Slot())+8+8+8+4)
	encoded = append(encoded, codecVersion, byte(canonical.Kind()))
	encoded = appendCodecString16(encoded, canonical.Namespace())
	encoded = appendCodecString16(encoded, canonical.Cursor())
	encoded = appendCodecString16(encoded, canonical.RevisionID())
	encoded = appendCodecString16(encoded, canonical.Slot())
	encoded = appendCodecUint64(encoded, canonical.SlotGeneration())
	encoded = appendCodecUint64(encoded, canonical.DataGeneration())
	encoded = appendCodecUint64(encoded, uint64(seconds))
	encoded = appendCodecUint32(encoded, nanos)
	return encoded, nil
}

func decodeStateEvent(encoded []byte) (policyengine.StateEvent, error) {
	reader := codecReader{data: encoded}
	if version, ok := reader.byte(); !ok || version != codecVersion {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	kind, ok := reader.byte()
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	namespace, ok := reader.string16(policyengine.MaxNamespaceBytes)
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	cursor, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	revisionID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	slot, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	slotGeneration, ok := reader.uint64()
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	dataGeneration, ok := reader.uint64()
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	seconds, ok := reader.int64()
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	nanos, ok := reader.uint32()
	if !ok || !reader.done() {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	when, ok := decodeCodecTime(seconds, nanos)
	if !ok {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace: namespace, Cursor: cursor, Kind: policyengine.StateEventKind(kind), RevisionID: revisionID,
		Slot: slot, SlotGeneration: slotGeneration, DataGeneration: dataGeneration, OccurredAt: when,
	})
	if err != nil {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func canonicalStateEvent(value policyengine.StateEvent) (policyengine.StateEvent, error) {
	result, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace: value.Namespace(), Cursor: value.Cursor(), Kind: value.Kind(), RevisionID: value.RevisionID(),
		Slot: value.Slot(), SlotGeneration: value.SlotGeneration(), DataGeneration: value.DataGeneration(),
		OccurredAt: value.OccurredAt().UTC(),
	})
	if err != nil {
		return policyengine.StateEvent{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func codecTime(value time.Time) (int64, uint32, bool) {
	if value.IsZero() {
		return 0, 0, false
	}
	utc := value.UTC()
	return utc.Unix(), uint32(utc.Nanosecond()), true
}

func decodeCodecTime(seconds int64, nanos uint32) (time.Time, bool) {
	if nanos >= uint32(time.Second) {
		return time.Time{}, false
	}
	result := time.Unix(seconds, int64(nanos)).UTC()
	if result.IsZero() {
		return time.Time{}, false
	}
	return result, true
}

func appendCodecUint16(destination []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendCodecUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendCodecUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendCodecString16(destination []byte, value string) []byte {
	destination = appendCodecUint16(destination, uint16(len(value)))
	return append(destination, value...)
}

type codecReader struct {
	data   []byte
	offset int
}

func (r *codecReader) byte() (byte, bool) {
	if r.offset >= len(r.data) {
		return 0, false
	}
	value := r.data[r.offset]
	r.offset++
	return value, true
}

func (r *codecReader) string16(maximum int) (string, bool) {
	if len(r.data)-r.offset < 2 {
		return "", false
	}
	length := int(binary.BigEndian.Uint16(r.data[r.offset : r.offset+2]))
	r.offset += 2
	if length > maximum || length > len(r.data)-r.offset {
		return "", false
	}
	value := string(r.data[r.offset : r.offset+length])
	r.offset += length
	return value, true
}

func (r *codecReader) bytes32(maximum int) ([]byte, bool) {
	if len(r.data)-r.offset < 4 {
		return nil, false
	}
	length := binary.BigEndian.Uint32(r.data[r.offset : r.offset+4])
	r.offset += 4
	if length > uint32(maximum) || uint64(length) > uint64(len(r.data)-r.offset) {
		return nil, false
	}
	end := r.offset + int(length)
	value := append([]byte(nil), r.data[r.offset:end]...)
	r.offset = end
	return value, true
}

func (r *codecReader) uint32() (uint32, bool) {
	if len(r.data)-r.offset < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(r.data[r.offset : r.offset+4])
	r.offset += 4
	return value, true
}

func (r *codecReader) uint64() (uint64, bool) {
	if len(r.data)-r.offset < 8 {
		return 0, false
	}
	value := binary.BigEndian.Uint64(r.data[r.offset : r.offset+8])
	r.offset += 8
	return value, true
}

func (r *codecReader) int64() (int64, bool) {
	value, ok := r.uint64()
	return int64(value), ok
}

func (r *codecReader) done() bool { return r.offset == len(r.data) }
