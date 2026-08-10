package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store/sqlite"
)

const (
	cliBusyTimeout                = 250 * time.Millisecond
	cliActivationHistoryRetention = 2
)

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		return writeCLIError(stderr, policyengine.ErrorInvalidArgument)
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	flags := flag.NewFlagSet("cadrena-policy-store", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", "", "")
	flagArgs, command, ok := cliArguments(args)
	if !ok || flags.Parse(flagArgs) != nil || flags.NArg() != 0 || *databasePath == "" || !filepath.IsAbs(*databasePath) {
		return writeCLIError(stderr, policyengine.ErrorInvalidArgument)
	}

	operationContext, cancel := context.WithTimeout(ctx, cliBusyTimeout)
	defer cancel()
	config := sqlite.Config{
		Path:                       *databasePath,
		BusyTimeout:                cliBusyTimeout,
		MaxReaders:                 1,
		Synchronous:                sqlite.SynchronousFull,
		ActivationHistoryRetention: cliActivationHistoryRetention,
		Clock:                      wallClock{},
	}

	switch command {
	case "plan":
		plan, err := sqlite.PlanMigrations(operationContext, config)
		if err != nil {
			return writeCLIResultError(stderr, err)
		}
		_, _ = fmt.Fprintf(stdout, "CURRENT %d\n", plan.Current)
		for _, pending := range plan.Pending {
			_, _ = fmt.Fprintf(stdout, "PENDING %d\n", pending.Version)
		}
		return 0
	case "migrate":
		result, err := sqlite.ApplyMigrations(operationContext, config)
		if err != nil {
			return writeCLIResultError(stderr, err)
		}
		for _, applied := range result.Applied {
			_, _ = fmt.Fprintf(stdout, "APPLIED %d\n", applied.Version)
		}
		_, _ = fmt.Fprintf(stdout, "CURRENT %d\n", result.Current)
		return 0
	case "validate":
		if err := sqlite.ValidateSchema(operationContext, config); err != nil {
			return writeCLIResultError(stderr, err)
		}
		_, _ = fmt.Fprintln(stdout, "VALID")
		return 0
	case "integrity":
		// FullIntegrityCheck owns its own bounded maintenance-lock wait. Passing
		// the caller context through preserves explicit cancellation/deadline
		// categories while a normal busy store is reported as UNAVAILABLE.
		if err := sqlite.FullIntegrityCheck(ctx, config); err != nil {
			return writeCLIResultError(stderr, err)
		}
		_, _ = fmt.Fprintln(stdout, "VALID")
		return 0
	default:
		return writeCLIError(stderr, policyengine.ErrorInvalidArgument)
	}
}

func cliArguments(args []string) ([]string, string, bool) {
	switch {
	case len(args) == 3 && args[0] == "--db":
		return args[:2], args[2], true
	case len(args) == 2 && strings.HasPrefix(args[0], "--db="):
		return args[:1], args[1], true
	default:
		return nil, "", false
	}
}

func writeCLIResultError(stderr io.Writer, err error) int {
	return writeCLIError(stderr, cliErrorCategory(err))
}

func writeCLIError(stderr io.Writer, category policyengine.ErrorCategory) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, category.String())
	}
	if category == policyengine.ErrorInvalidArgument {
		return 2
	}
	return 1
}

func cliErrorCategory(err error) policyengine.ErrorCategory {
	var engineErr *policyengine.EngineError
	if errors.As(err, &engineErr) {
		return engineErr.Category()
	}
	return policyengine.ErrorInternal
}
