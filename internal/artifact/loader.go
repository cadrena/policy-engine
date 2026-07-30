// Package artifact loads canonical artifacts exclusively through the tagged
// public Conductera DSL artifact API.
package artifact

import "github.com/cadrena/dsl"

// Loader compiles local source and decodes stored canonical DSL artifacts.
type Loader struct{}

// NewLoader constructs a stateless canonical artifact loader.
func NewLoader() Loader { return Loader{} }

// Compile parses, validates, compiles, and canonicalizes local DSL source.
func (Loader) Compile(sourceName string, source []byte) (*dsl.Artifact, error) {
	return dsl.CompileArtifact(sourceName, source)
}

// Decode validates and loads canonical artifact bytes.
func (Loader) Decode(encoded []byte) (*dsl.Artifact, error) {
	return dsl.DecodeArtifact(encoded)
}
