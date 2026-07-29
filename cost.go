package policyengine

import "github.com/conductera/dsl"

const (
	// Aggregate costs count exact dynamic bytes plus deterministic conservative
	// metadata for fields, collections, scalar tags, timestamps, and digests.
	// They do not depend on Go's in-memory object layout or map iteration order.
	valueMetadataBytes      = 9
	collectionMetadataBytes = 8
	fieldMetadataBytes      = 8
	timestampBytes          = 40
	digestBytes             = 32
	uint64Bytes             = 8
	boolBytes               = 1
	enumBytes               = 1
)

func addTextCost(budget *budgetCounter, value string) error {
	if err := budget.add(fieldMetadataBytes); err != nil {
		return err
	}
	return budget.add(len(value))
}

func addBytesCost(budget *budgetCounter, value []byte) error {
	if err := budget.add(fieldMetadataBytes); err != nil {
		return err
	}
	return budget.add(len(value))
}

func addFixedFieldCost(budget *budgetCounter, size int) error {
	if err := budget.add(fieldMetadataBytes); err != nil {
		return err
	}
	return budget.add(size)
}

func addValueCost(budget *budgetCounter, value Value) error {
	if err := budget.add(valueMetadataBytes); err != nil {
		return err
	}
	if value.kind == ValueKindString {
		return budget.add(len(value.text))
	}
	return nil
}

func addEntityRefCost(budget *budgetCounter, entity dsl.EntityRef) error {
	if err := addTextCost(budget, entity.Type); err != nil {
		return err
	}
	return addTextCost(budget, entity.ID)
}

func addAttributePathCost(budget *budgetCounter, path []string) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, segment := range path {
		if err := addTextCost(budget, segment); err != nil {
			return err
		}
	}
	return nil
}

func addSubjectRefCost(budget *budgetCounter, subject dsl.SubjectRef) error {
	if err := addTextCost(budget, subject.Type); err != nil {
		return err
	}
	if err := addTextCost(budget, subject.ID); err != nil {
		return err
	}
	return addTextCost(budget, subject.Relation)
}

func addTupleCost(budget *budgetCounter, tuple dsl.Tuple) error {
	if err := addEntityRefCost(budget, tuple.Resource); err != nil {
		return err
	}
	if err := addTextCost(budget, tuple.Relation); err != nil {
		return err
	}
	return addSubjectRefCost(budget, tuple.Subject)
}

func addRelationshipTupleCost(budget *budgetCounter, tuple RelationshipTuple) error {
	if err := addTupleCost(budget, tuple.tuple); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, boolBytes); err != nil {
		return err
	}
	if tuple.hasExpiry {
		return addFixedFieldCost(budget, timestampBytes)
	}
	return nil
}

func addAttributeCost(budget *budgetCounter, attribute Attribute) error {
	if err := addEntityRefCost(budget, attribute.entity); err != nil {
		return err
	}
	if err := addAttributePathCost(budget, attribute.path); err != nil {
		return err
	}
	return addValueCost(budget, attribute.value)
}

func addContextualDataCost(budget *budgetCounter, data ContextualData) error {
	if err := budget.addMany(2, collectionMetadataBytes); err != nil {
		return err
	}
	for _, tuple := range data.tuples {
		if err := addRelationshipTupleCost(budget, tuple); err != nil {
			return err
		}
	}
	for _, attribute := range data.attributes {
		if err := addAttributeCost(budget, attribute); err != nil {
			return err
		}
	}
	return nil
}

func addArgumentsCost(budget *budgetCounter, arguments map[string]Value) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for key, value := range arguments {
		if err := addTextCost(budget, key); err != nil {
			return err
		}
		if err := addValueCost(budget, value); err != nil {
			return err
		}
	}
	return nil
}

func addSelectorCost(budget *budgetCounter, selector Selector) error {
	if err := addTextCost(budget, selector.slot); err != nil {
		return err
	}
	return addTextCost(budget, selector.revisionID)
}

func addCheckRequestCost(budget *budgetCounter, input CheckRequestInput) error {
	if err := addTextCost(budget, input.Namespace); err != nil {
		return err
	}
	if err := addSelectorCost(budget, input.Selector); err != nil {
		return err
	}
	if err := addEntityRefCost(budget, input.Subject); err != nil {
		return err
	}
	if err := addEntityRefCost(budget, input.Resource); err != nil {
		return err
	}
	if err := addTextCost(budget, input.Action); err != nil {
		return err
	}
	if err := addArgumentsCost(budget, input.Arguments); err != nil {
		return err
	}
	if err := addContextualDataCost(budget, input.ContextualData); err != nil {
		return err
	}
	if err := addBytesCost(budget, input.ApprovalEvidence); err != nil {
		return err
	}
	if err := addBytesCost(budget, input.DelegationEvidence); err != nil {
		return err
	}
	return addFixedFieldCost(budget, uint64Bytes)
}

func addBatchItemCost(budget *budgetCounter, item BatchCheckItem) error {
	if err := addEntityRefCost(budget, item.subject); err != nil {
		return err
	}
	if err := addEntityRefCost(budget, item.resource); err != nil {
		return err
	}
	if err := addTextCost(budget, item.action); err != nil {
		return err
	}
	return addArgumentsCost(budget, item.arguments)
}

func addBatchRequestCost(budget *budgetCounter, input BatchCheckRequestInput) error {
	if err := addTextCost(budget, input.Namespace); err != nil {
		return err
	}
	if err := addSelectorCost(budget, input.Selector); err != nil {
		return err
	}
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, item := range input.Items {
		if err := addBatchItemCost(budget, item); err != nil {
			return err
		}
	}
	if err := addContextualDataCost(budget, input.ContextualData); err != nil {
		return err
	}
	if err := addBytesCost(budget, input.ApprovalEvidence); err != nil {
		return err
	}
	if err := addBytesCost(budget, input.DelegationEvidence); err != nil {
		return err
	}
	return addFixedFieldCost(budget, uint64Bytes)
}

func addWriteDataRequestCost(budget *budgetCounter, input WriteDataRequestInput) error {
	for _, value := range []string{input.Namespace, input.ValidationRevisionID, input.IdempotencyKey} {
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	if err := budget.addMany(4, collectionMetadataBytes); err != nil {
		return err
	}
	for _, tuple := range input.TupleWrites {
		if err := addRelationshipTupleCost(budget, tuple); err != nil {
			return err
		}
	}
	for _, tuple := range input.TupleDeletes {
		if err := addTupleCost(budget, tuple.tuple); err != nil {
			return err
		}
	}
	for _, attribute := range input.AttributeWrites {
		if err := addAttributeCost(budget, attribute); err != nil {
			return err
		}
	}
	for _, attribute := range input.AttributeDeletes {
		if err := addEntityRefCost(budget, attribute.entity); err != nil {
			return err
		}
		if err := addAttributePathCost(budget, attribute.path); err != nil {
			return err
		}
	}
	return nil
}

func addIdentifiersCost(budget *budgetCounter, values []string) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, value := range values {
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	return nil
}

func addDecisionResultCost(budget *budgetCounter, input DecisionResultInput) error {
	for _, value := range []string{input.DecisionID, input.ReasonCode, input.RevisionID} {
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	for _, size := range []int{enumBytes, uint64Bytes, uint64Bytes, timestampBytes, boolBytes, boolBytes, boolBytes} {
		if err := addFixedFieldCost(budget, size); err != nil {
			return err
		}
	}
	return addIdentifiersCost(budget, input.Requirements)
}

func addDecisionResultValueCost(budget *budgetCounter, result DecisionResult) error {
	return addDecisionResultCost(budget, DecisionResultInput{
		Decision:     result.decision,
		DecisionID:   result.decisionID,
		ReasonCode:   result.reasonCode,
		RevisionID:   result.revisionID,
		Requirements: result.requirements,
	})
}

func addExplainResponseCost(budget *budgetCounter, result DecisionResult, steps []ExplainStep) error {
	if err := addDecisionResultValueCost(budget, result); err != nil {
		return err
	}
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, step := range steps {
		if err := addTextCost(budget, step.schemaPath); err != nil {
			return err
		}
		if err := addTextCost(budget, step.operator); err != nil {
			return err
		}
		if err := addFixedFieldCost(budget, boolBytes); err != nil {
			return err
		}
	}
	return nil
}

func addEvidenceBindingCost(budget *budgetCounter, binding EvidenceBinding) error {
	if err := addFixedFieldCost(budget, digestBytes); err != nil {
		return err
	}
	if err := addTextCost(budget, binding.namespace); err != nil {
		return err
	}
	if err := addSelectorCost(budget, binding.selector); err != nil {
		return err
	}
	if err := addTextCost(budget, binding.revisionID); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, timestampBytes); err != nil {
		return err
	}
	return addFixedFieldCost(budget, digestBytes)
}

func addApprovalVerificationRequestCost(budget *budgetCounter, binding EvidenceBinding, requirementIDs []string, evidence []byte) error {
	if err := addEvidenceBindingCost(budget, binding); err != nil {
		return err
	}
	if err := addIdentifiersCost(budget, requirementIDs); err != nil {
		return err
	}
	return addBytesCost(budget, evidence)
}

func addDelegationVerificationRequestCost(budget *budgetCounter, binding EvidenceBinding, evidence []byte) error {
	if err := addEvidenceBindingCost(budget, binding); err != nil {
		return err
	}
	return addBytesCost(budget, evidence)
}

func addPublishRequestCost(budget *budgetCounter, namespace, sourceName string, source []byte) error {
	if err := addTextCost(budget, namespace); err != nil {
		return err
	}
	if err := addTextCost(budget, sourceName); err != nil {
		return err
	}
	return addBytesCost(budget, source)
}

func addCallerCost(budget *budgetCounter, id string, attributes map[string]string) error {
	if err := addTextCost(budget, id); err != nil {
		return err
	}
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for key, value := range attributes {
		if err := addTextCost(budget, key); err != nil {
			return err
		}
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	return nil
}

func addGrantCost(budget *budgetCounter, grant Grant) error {
	if err := addTextCost(budget, grant.namespacePattern); err != nil {
		return err
	}
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, capability := range grant.capabilities {
		if err := addTextCost(budget, string(capability)); err != nil {
			return err
		}
	}
	return nil
}

func addCallerAuthorizationCost(budget *budgetCounter, grants []Grant) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, grant := range grants {
		if err := addGrantCost(budget, grant); err != nil {
			return err
		}
	}
	return nil
}

func addRevisionMetadataCost(budget *budgetCounter, revision RevisionMetadata) error {
	if err := addTextCost(budget, revision.namespace); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, 64); err != nil {
		return err
	}
	return addFixedFieldCost(budget, timestampBytes)
}

func addRevisionPageCost(budget *budgetCounter, revisions []RevisionMetadata, nextCursor string) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	if err := addTextCost(budget, nextCursor); err != nil {
		return err
	}
	for _, revision := range revisions {
		if err := addRevisionMetadataCost(budget, revision); err != nil {
			return err
		}
	}
	return nil
}

func addActivationCost(budget *budgetCounter, activation Activation) error {
	for _, value := range []string{activation.namespace, activation.slot, activation.revisionID} {
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	return addFixedFieldCost(budget, timestampBytes)
}

func addActivationHistoryPageCost(budget *budgetCounter, activations []Activation, nextCursor string) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	if err := addTextCost(budget, nextCursor); err != nil {
		return err
	}
	for _, activation := range activations {
		if err := addActivationCost(budget, activation); err != nil {
			return err
		}
	}
	return nil
}

func addStateEventCost(budget *budgetCounter, event StateEvent) error {
	for _, value := range []string{event.namespace, event.cursor, event.revisionID, event.slot} {
		if err := addTextCost(budget, value); err != nil {
			return err
		}
	}
	if err := addFixedFieldCost(budget, enumBytes); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, uint64Bytes); err != nil {
		return err
	}
	return addFixedFieldCost(budget, timestampBytes)
}

func addEventPageCost(budget *budgetCounter, events []StateEvent, nextCursor string) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	if err := addTextCost(budget, nextCursor); err != nil {
		return err
	}
	for _, event := range events {
		if err := addStateEventCost(budget, event); err != nil {
			return err
		}
	}
	return nil
}

func addComponentStatusCost(budget *budgetCounter, component ComponentStatus) error {
	if err := addTextCost(budget, component.name); err != nil {
		return err
	}
	if err := addFixedFieldCost(budget, enumBytes); err != nil {
		return err
	}
	return addTextCost(budget, component.reasonCode)
}

func addStatusResponseCost(budget *budgetCounter, _ bool, components []ComponentStatus) error {
	if err := addFixedFieldCost(budget, boolBytes); err != nil {
		return err
	}
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, component := range components {
		if err := addComponentStatusCost(budget, component); err != nil {
			return err
		}
	}
	return nil
}

func addBatchResponseCost(budget *budgetCounter, results []DecisionResult) error {
	if err := budget.add(collectionMetadataBytes); err != nil {
		return err
	}
	for _, result := range results {
		if err := addDecisionResultValueCost(budget, result); err != nil {
			return err
		}
	}
	return nil
}

func contextualWorkItems(data ContextualData) int {
	return len(data.tuples) + len(data.attributes)
}
