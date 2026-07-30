package policyengine_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

func TestTask5StateEventRejectsNonApplicableFields(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC)
	revisionID := testRevisionID(t)
	tests := []policyengine.StateEventInput{
		{Namespace: "acme", Cursor: "1", Kind: policyengine.StateEventRevisionPublished, RevisionID: revisionID, Slot: "stable", OccurredAt: now},
		{Namespace: "acme", Cursor: "2", Kind: policyengine.StateEventRevisionPublished, RevisionID: revisionID, SlotGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "3", Kind: policyengine.StateEventRevisionPublished, RevisionID: revisionID, DataGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "4", Kind: policyengine.StateEventSlotActivated, RevisionID: revisionID, Slot: "stable", SlotGeneration: 1, DataGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "5", Kind: policyengine.StateEventDataWritten, RevisionID: revisionID, DataGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "6", Kind: policyengine.StateEventDataWritten, Slot: "stable", DataGeneration: 1, OccurredAt: now},
		{Namespace: "bad\x00namespace", Cursor: "7", Kind: policyengine.StateEventDataWritten, DataGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "bad\u202ecursor", Kind: policyengine.StateEventDataWritten, DataGeneration: 1, OccurredAt: now},
	}
	for index, input := range tests {
		if _, err := policyengine.NewStateEvent(input); err == nil {
			t.Fatalf("case %d accepted an invalid state-event union", index)
		}
	}

	valid := []policyengine.StateEventInput{
		{Namespace: "acme", Cursor: "8", Kind: policyengine.StateEventRevisionPublished, RevisionID: revisionID, OccurredAt: now},
		{Namespace: "acme", Cursor: "9", Kind: policyengine.StateEventSlotActivated, RevisionID: revisionID, Slot: "stable", SlotGeneration: 1, OccurredAt: now},
		{Namespace: "acme", Cursor: "10", Kind: policyengine.StateEventDataWritten, DataGeneration: 1, OccurredAt: now},
	}
	for index, input := range valid {
		if _, err := policyengine.NewStateEvent(input); err != nil {
			t.Fatalf("valid case %d rejected: %v", index, err)
		}
	}
}

func TestTask5SensitiveValuesAreRedactedByDefaultFormatting(t *testing.T) {
	t.Parallel()

	const (
		secretCaller    = "caller-private-9f2a"
		secretNamespace = "tenant-private-6b31"
		secretSource    = "entity secret_policy_marker {}"
		secretEvidence  = "approval-private-13d7"
		secretSubject   = "subject-private-8c44"
	)

	caller, err := policyengine.NewCaller(secretCaller, map[string]string{"token_hint": "attribute-private-2a11"})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	contextual, err := policyengine.NewContextualData(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkInput := policyengine.CheckRequestInput{
		Namespace:        secretNamespace,
		Selector:         selector,
		Subject:          dsl.EntityRef{Type: "user", ID: secretSubject},
		Resource:         dsl.EntityRef{Type: "document", ID: "resource-private-72c0"},
		Action:           "action-private-f170",
		Arguments:        map[string]policyengine.Value{"argument-private-42a8": mustStringValue(t, "value-private-0d91")},
		ContextualData:   contextual,
		ApprovalEvidence: []byte(secretEvidence),
	}
	check, err := policyengine.NewCheckRequest(checkInput)
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewBatchCheckItem(checkInput.Subject, checkInput.Resource, checkInput.Action, checkInput.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	batchInput := policyengine.BatchCheckRequestInput{
		Namespace: secretNamespace, Selector: selector, Items: []policyengine.BatchCheckItem{item}, ContextualData: contextual,
		ApprovalEvidence: []byte(secretEvidence),
	}
	batch, err := policyengine.NewBatchCheckRequest(batchInput)
	if err != nil {
		t.Fatal(err)
	}
	publish, err := policyengine.NewPublishRequest(secretNamespace, "source-private-7f51", []byte(secretSource))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: secretNamespace, Selector: selector,
		RevisionID: testRevisionID(t), SlotGeneration: 1,
		EvaluatedAt: time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC),
		Fingerprint: policyengine.NewEvidenceFingerprint([32]byte{0x9f, 0x2a}),
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := policyengine.NewApprovalVerificationRequest(binding, []string{"requirement-private-918e"}, []byte(secretEvidence))
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := policyengine.NewDelegationVerificationRequest(binding, []byte("delegation-private-b304"))
	if err != nil {
		t.Fatal(err)
	}

	values := []any{caller, publish, checkInput, check, item, batchInput, batch, binding, approval, delegation}
	secrets := []string{
		secretCaller, secretNamespace, secretSource, secretEvidence, secretSubject,
		"attribute-private-2a11", "resource-private-72c0", "action-private-f170",
		"argument-private-42a8", "value-private-0d91", "source-private-7f51",
		"requirement-private-918e", "delegation-private-b304", "9f2a",
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			for _, secret := range secrets {
				if strings.Contains(output, secret) {
					t.Fatalf("%T with %s leaked %q in %q", value, format, secret, output)
				}
			}
		}

		var buffer bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buffer, nil))
		logger.Info("sensitive", "value", value)
		output := buffer.String()
		for _, secret := range secrets {
			if strings.Contains(output, secret) {
				t.Fatalf("%T slog leaked %q in %q", value, secret, output)
			}
		}
	}
}
