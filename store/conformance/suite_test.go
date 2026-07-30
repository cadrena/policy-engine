package conformance_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cadrena/policy-engine/store/conformance"
)

func TestConformanceCaseManifestIsStableUniqueAndDefensive(t *testing.T) {
	t.Parallel()

	names := conformance.CaseNames()
	if len(names) < 8 {
		t.Fatalf("CaseNames() count = %d, want comprehensive contract", len(names))
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, " \t\n") {
			t.Fatalf("invalid case name %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate case name %q", name)
		}
		seen[name] = struct{}{}
	}
	names[0] = "mutated"
	if conformance.CaseNames()[0] == "mutated" {
		t.Fatal("CaseNames returned aliased manifest")
	}
}

func TestReferenceModelPassesFullConformance(t *testing.T) {
	conformance.Run(t, func(tb testing.TB) conformance.Fixture {
		return newReferenceFixture(tb)
	})
}

func TestConformanceHarnessRejectsBrokenAdapter(t *testing.T) {
	if os.Getenv("POLICYENGINE_BROKEN_CONFORMANCE_CHILD") == "1" {
		created := 0
		conformance.Run(t, func(testing.TB) conformance.Fixture {
			created++
			return conformance.Fixture{
				Store:                      completeContract{},
				ActivationHistoryRetention: 2,
				ArmNextEventAppendFailure:  func() {},
				ArmNextSnapshotReadBlock:   func() {},
				PauseNextSnapshotRead: func() conformance.SnapshotReadPause {
					entered := make(chan struct{})
					close(entered)
					return conformance.SnapshotReadPause{Entered: entered, Release: func() {}}
				},
				PauseNextDataCommit: func() conformance.DataCommitPause {
					entered := make(chan struct{})
					close(entered)
					return conformance.DataCommitPause{Entered: entered, Release: func() {}}
				},
				PauseNextRevisionCommit: func() conformance.RevisionCommitPause {
					entered := make(chan struct{})
					close(entered)
					contended := make(chan struct{})
					close(contended)
					waiterWoke := make(chan struct{})
					close(waiterWoke)
					return conformance.RevisionCommitPause{
						Entered: entered, Contended: contended, WaiterWoke: waiterWoke,
						Release: func() {}, ResumeWaiter: func() {},
					}
				},
				ExpireEvents: func(context.Context, string, string) error {
					return nil
				},
			}
		})
		if created != len(conformance.CaseNames()) {
			t.Fatalf("factory calls = %d, want %d fresh fixtures", created, len(conformance.CaseNames()))
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestConformanceHarnessRejectsBrokenAdapter$", "-test.v")
	command.Env = append(os.Environ(), "POLICYENGINE_BROKEN_CONFORMANCE_CHILD=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("broken adapter unexpectedly passed:\n%s", output)
	}
	text := string(output)
	for _, name := range conformance.CaseNames() {
		if !strings.Contains(text, name) {
			t.Errorf("child output did not execute case %q:\n%s", name, text)
		}
	}
}
