package sqlite

import (
	"path/filepath"
	"testing"

	storeconformance "github.com/cadrena/policy-engine/store/conformance"
)

func TestStoreConformance(t *testing.T) {
	names := storeconformance.CaseNames()
	factory := sqliteConformanceFactory(t)
	created := 0
	storeconformance.Run(t, func(tb testing.TB) storeconformance.Fixture {
		created++
		return factory(tb)
	})
	if created != len(names) {
		t.Fatalf("SQLite fixture calls = %d, want every shared conformance case (%d)", created, len(names))
	}
}

func sqliteConformanceFactory(t *testing.T) storeconformance.Factory {
	t.Helper()
	return func(tb testing.TB) storeconformance.Fixture {
		tb.Helper()
		// The shared suite deliberately keeps multiple historical snapshots
		// pinned at once. Give this integration fixture enough reader permits to
		// exercise those views while the dedicated pool tests cover small bounds.
		config := validConfig(filepath.Join(tb.TempDir(), "policy.db"))
		config.MaxReaders = 8
		adapter, hooks := openMigratedStoreWithHooksForTest(tb, config)
		return storeconformance.Fixture{
			Store:                      adapter,
			ActivationHistoryRetention: adapter.activationHistoryRetention,
			ExpireEvents:               adapter.expireEvents,
			ArmNextEventAppendFailure:  hooks.armNextEventAppendFailure,
			ArmNextSnapshotReadBlock:   hooks.armNextSnapshotReadBlock,
			PauseNextSnapshotRead: func() storeconformance.SnapshotReadPause {
				pause := hooks.pauseNextSnapshotRead()
				return storeconformance.SnapshotReadPause{Entered: pause.entered, Release: pause.Release}
			},
			PauseNextDataCommit: func() storeconformance.DataCommitPause {
				pause := adapter.pauseNextDataCommit()
				return storeconformance.DataCommitPause{Entered: pause.entered, Release: pause.Release}
			},
			PauseNextRevisionCommit: func() storeconformance.RevisionCommitPause {
				pause := adapter.pauseNextRevisionCommit()
				return storeconformance.RevisionCommitPause{
					Entered: pause.entered, Contended: pause.contendedSignal, WaiterWoke: pause.waiterWokeSignal,
					Release: pause.Release, ResumeWaiter: pause.ResumeWaiter,
				}
			},
		}
	}
}

func TestSQLiteConformanceCaseManifestMatchesSharedExport(t *testing.T) {
	// SQLite deliberately consumes the same exported manifest as memory; this
	// checks that it remains non-empty, stable enough to register, and copied.
	names := storeconformance.CaseNames()
	if len(names) == 0 || sqliteConformanceFactory(t) == nil {
		t.Fatal("SQLite conformance factory does not expose the shared manifest")
	}
	first := names[0]
	names[0] = "mutated"
	if storeconformance.CaseNames()[0] != first {
		t.Fatal("SQLite observed an aliased conformance case manifest")
	}
}
