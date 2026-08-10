package sqlite

import (
	"bytes"
	"math"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

const (
	attributeValueString  byte = 1
	attributeValueInteger byte = 2
	attributeValueBoolean byte = 3
	attributeValueNull    byte = 4
)

// encodeAttributePath gives every structured path its own versioned encoding
// so prefixes remain unambiguous ("a", "bc") never aliases ("ab", "c")).
func encodeAttributePath(path []string) ([]byte, error) {
	probe, err := policyengine.NewAttributeKeyPath(dsl.EntityRef{Type: "codec", ID: "codec"}, path)
	if err != nil {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	canonical := probe.Path()
	if len(canonical) > math.MaxUint32 {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := make([]byte, 0, 1+4+len(canonical)*2)
	encoded = append(encoded, codecVersion)
	encoded = appendCodecUint32(encoded, uint32(len(canonical)))
	for _, segment := range canonical {
		encoded = appendCodecString16(encoded, segment)
	}
	return encoded, nil
}

func decodeAttributePath(encoded []byte) ([]string, error) {
	reader := codecReader{data: encoded}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	count, ok := reader.uint32()
	if !ok || count == 0 || count > uint32(policyengine.MaxAggregateWorkItems) || uint64(count)*2 > uint64(len(encoded)-reader.offset) {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	path := make([]string, 0, int(count))
	for range count {
		segment, ok := reader.string16(policyengine.MaxIdentifierBytes)
		if !ok {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		path = append(path, segment)
	}
	if !reader.done() {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	probe, err := policyengine.NewAttributeKeyPath(dsl.EntityRef{Type: "codec", ID: "codec"}, path)
	if err != nil {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	return probe.Path(), nil
}

func encodeAttributeKey(value policyengine.AttributeKey) ([]byte, error) {
	canonical, err := policyengine.NewAttributeKeyPath(value.Entity(), value.Path())
	if err != nil {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	path, err := encodeAttributePath(canonical.Path())
	if err != nil {
		return nil, err
	}
	if len(path) > policyengine.MaxAggregateInputBytes {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	entity := canonical.Entity()
	encoded := make([]byte, 0, 1+4+len(entity.Type)+len(entity.ID)+len(path))
	encoded = append(encoded, codecVersion)
	encoded = appendCodecString16(encoded, entity.Type)
	encoded = appendCodecString16(encoded, entity.ID)
	encoded = appendCodecUint32(encoded, uint32(len(path)))
	encoded = append(encoded, path...)
	return encoded, nil
}

func decodeAttributeKey(encoded []byte) (policyengine.AttributeKey, error) {
	reader := codecReader{data: encoded}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	entityType, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	entityID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	pathEncoded, ok := reader.bytes32(policyengine.MaxAggregateInputBytes)
	if !ok || !reader.done() {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	path, err := decodeAttributePath(pathEncoded)
	if err != nil {
		return policyengine.AttributeKey{}, err
	}
	result, err := policyengine.NewAttributeKeyPath(dsl.EntityRef{Type: entityType, ID: entityID}, path)
	if err != nil {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func encodeAttributeValue(value policyengine.Value) ([]byte, error) {
	encoded := []byte{codecVersion}
	switch value.Kind() {
	case policyengine.ValueKindString:
		text, ok := value.StringValue()
		if !ok || len(text) > policyengine.MaxStringValueBytes {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		encoded = append(encoded, attributeValueString)
		encoded = appendCodecUint32(encoded, uint32(len(text)))
		return append(encoded, text...), nil
	case policyengine.ValueKindInteger:
		integer, ok := value.Integer()
		if !ok {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		encoded = append(encoded, attributeValueInteger)
		return appendCodecUint64(encoded, uint64(integer)), nil
	case policyengine.ValueKindBoolean:
		boolean, ok := value.Boolean()
		if !ok {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		encoded = append(encoded, attributeValueBoolean)
		if boolean {
			return append(encoded, 1), nil
		}
		return append(encoded, 0), nil
	case policyengine.ValueKindNull:
		if !value.IsNull() {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		return append(encoded, attributeValueNull), nil
	default:
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
}

func decodeAttributeValue(encoded []byte) (policyengine.Value, error) {
	reader := codecReader{data: encoded}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
	}
	kind, ok := reader.byte()
	if !ok {
		return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
	}
	switch kind {
	case attributeValueString:
		text, ok := reader.bytes32(policyengine.MaxStringValueBytes)
		if !ok || !reader.done() {
			return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
		}
		result, err := policyengine.NewStringValue(string(text))
		if err != nil {
			return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return result, nil
	case attributeValueInteger:
		integer, ok := reader.int64()
		if !ok || !reader.done() {
			return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return policyengine.NewIntegerValue(integer), nil
	case attributeValueBoolean:
		boolean, ok := reader.byte()
		if !ok || !reader.done() || (boolean != 0 && boolean != 1) {
			return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return policyengine.NewBooleanValue(boolean == 1), nil
	case attributeValueNull:
		if !reader.done() {
			return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
		}
		return policyengine.NewNullValue(), nil
	default:
		return policyengine.Value{}, sqliteError(policyengine.ErrorIntegrity)
	}
}

type durableAttribute struct {
	key       []byte
	attribute policyengine.Attribute
	path      []byte
	value     []byte
}

func canonicalDurableAttribute(value policyengine.Attribute) (durableAttribute, error) {
	canonical, err := policyengine.NewAttributePath(value.Entity(), value.Path(), value.Value())
	if err != nil {
		return durableAttribute{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	keyValue, err := policyengine.NewAttributeKeyPath(canonical.Entity(), canonical.Path())
	if err != nil {
		return durableAttribute{}, sqliteError(policyengine.ErrorInternal)
	}
	key, err := encodeAttributeKey(keyValue)
	if err != nil {
		return durableAttribute{}, err
	}
	path, err := encodeAttributePath(canonical.Path())
	if err != nil {
		return durableAttribute{}, err
	}
	encodedValue, err := encodeAttributeValue(canonical.Value())
	if err != nil {
		return durableAttribute{}, err
	}
	return durableAttribute{key: key, attribute: canonical, path: path, value: encodedValue}, nil
}

func decodeDurableAttribute(key, path, encodedValue []byte, entityType, entityID string) (policyengine.Attribute, error) {
	decodedPath, err := decodeAttributePath(path)
	if err != nil {
		return policyengine.Attribute{}, err
	}
	decodedValue, err := decodeAttributeValue(encodedValue)
	if err != nil {
		return policyengine.Attribute{}, err
	}
	result, err := policyengine.NewAttributePath(dsl.EntityRef{Type: entityType, ID: entityID}, decodedPath, decodedValue)
	if err != nil {
		return policyengine.Attribute{}, sqliteError(policyengine.ErrorIntegrity)
	}
	attributeKey, err := policyengine.NewAttributeKeyPath(result.Entity(), result.Path())
	if err != nil {
		return policyengine.Attribute{}, sqliteError(policyengine.ErrorIntegrity)
	}
	expected, err := encodeAttributeKey(attributeKey)
	if err != nil || !bytes.Equal(expected, key) {
		return policyengine.Attribute{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func strictAttributePrefixes(key policyengine.AttributeKey) ([][]byte, error) {
	path := key.Path()
	result := make([][]byte, 0, len(path)-1)
	for length := 1; length < len(path); length++ {
		prefix, err := policyengine.NewAttributeKeyPath(key.Entity(), path[:length])
		if err != nil {
			return nil, sqliteError(policyengine.ErrorInternal)
		}
		encoded, err := encodeAttributeKey(prefix)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	return result, nil
}

func attributeKeyFromAttribute(value policyengine.Attribute) (policyengine.AttributeKey, error) {
	result, err := policyengine.NewAttributeKeyPath(value.Entity(), value.Path())
	if err != nil {
		return policyengine.AttributeKey{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}
