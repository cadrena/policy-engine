package conformance_test

import (
	"context"
	"testing"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

func TestStoreContractComposesRevisionAndSlotCapabilities(t *testing.T) {
	t.Parallel()
	var candidate revisionSlotContract
	var _ store.RevisionStore = candidate
	var _ store.SlotStore = candidate
}

type revisionSlotContract struct{}

func (revisionSlotContract) PutRevision(context.Context, store.RevisionWrite) (store.PutRevisionResult, error) {
	return store.PutRevisionResult{}, nil
}

func (revisionSlotContract) GetRevision(context.Context, policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	return store.RevisionRecord{}, nil
}

func (revisionSlotContract) ListRevisions(context.Context, policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error) {
	return policyengine.ListRevisionsResponse{}, nil
}

func (revisionSlotContract) Activate(context.Context, policyengine.ActivateRequest) (policyengine.ActivateResponse, error) {
	return policyengine.ActivateResponse{}, nil
}

func (revisionSlotContract) Resolve(context.Context, policyengine.ResolveRequest) (policyengine.ResolveResponse, error) {
	return policyengine.ResolveResponse{}, nil
}

func (revisionSlotContract) ListActivationHistory(context.Context, policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error) {
	return policyengine.ListActivationHistoryResponse{}, nil
}

func (revisionSlotContract) GetDataGeneration(context.Context, policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	return policyengine.GetDataGenerationResponse{}, nil
}

func (revisionSlotContract) WriteData(context.Context, policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error) {
	return policyengine.WriteDataResponse{}, nil
}

func (revisionSlotContract) OpenSnapshot(context.Context, store.SnapshotRequest) (store.Snapshot, error) {
	return nil, nil
}
