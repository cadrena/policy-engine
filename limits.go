package policyengine

import "github.com/cadrena/dsl"

// Stable public V1 hard maxima. Per-request or deployment configuration may
// lower these values but must never raise them.
const (
	MaxIdentifierBytes       = 1024
	MaxStringValueBytes      = 64 << 10
	MaxNamespaceBytes        = MaxIdentifierBytes
	MaxNamespacePatternBytes = MaxIdentifierBytes + 1
	MaxCallerAttributes      = 128
	MaxCallerGrants          = 128
	MaxCapabilitiesPerGrant  = 16
	MaxSourceNameBytes       = MaxIdentifierBytes
	MaxPolicySourceBytes     = 1 << 20 // dsl.DefaultLimits().MaxSourceBytes in DSL v1.0.0.
	MaxPolicyArtifactBytes   = dsl.DefaultArtifactMaxBytes
	MaxArgumentItems         = 128
	MaxContextualTuples      = 1024
	MaxContextualAttributes  = 1024
	MaxBatchItems            = 1000
	MaxMutationItems         = 4096
	MaxEvidenceBytes         = 64 << 10
	MaxVerifierOutputItems   = 1024
	MaxPageRequestItems      = 1000
	MaxPageResponseItems     = 1000
	MaxExplainSteps          = 4096
	MaxStatusComponents      = 256
	MaxEventPageItems        = 1000
	MaxAggregateInputBytes   = 4 << 20
	MaxAggregateOutputBytes  = 4 << 20
	MaxAuthorizerOutputBytes = 1 << 20
	MaxVerifierOutputBytes   = 4 << 20
	MaxEventPageBytes        = 4 << 20
	MaxAggregateWorkItems    = 100_000
)

type budgetCounter struct {
	used int
	max  int
}

func (b *budgetCounter) add(size int) error {
	if size < 0 || b.used < 0 || b.max < 0 || size > b.max || b.used > b.max-size {
		return resourceExhausted()
	}
	b.used += size
	return nil
}

func (b *budgetCounter) addMany(count, size int) error {
	if count < 0 || size < 0 || b.used < 0 || b.max < 0 || (count != 0 && size > b.max/count) {
		return resourceExhausted()
	}
	return b.add(count * size)
}

func resourceExhausted() error { return engineError(ErrorResourceExhausted) }
