package sqlite

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func TestConfigValidateRejectsInvalidDurableDatabaseConfiguration(t *testing.T) {
	// This catches any production change that drops a configuration boundary:
	// accepting a memory/URI/relative location, unusable timeouts or limits,
	// non-FULL synchronization, or a nil clock would let an unsafe store open.
	t.Parallel()

	validPath := filepath.Join(t.TempDir(), "policy.db")
	missingParent := filepath.Join(t.TempDir(), "missing", "policy.db")
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := writeTestFile(parentFile); err != nil {
		t.Fatal(err)
	}

	var typedNilClock *nilClock
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "empty path", edit: func(c *Config) { c.Path = "" }},
		{name: "relative path", edit: func(c *Config) { c.Path = "policy.db" }},
		{name: "memory database", edit: func(c *Config) { c.Path = ":memory:" }},
		{name: "file URI", edit: func(c *Config) { c.Path = "file:" + validPath }},
		{name: "memory URI", edit: func(c *Config) { c.Path = "file::memory:?cache=shared" }},
		{name: "non-positive timeout", edit: func(c *Config) { c.BusyTimeout = 0 }},
		{name: "negative timeout", edit: func(c *Config) { c.BusyTimeout = -time.Millisecond }},
		{name: "sub-millisecond timeout", edit: func(c *Config) { c.BusyTimeout = time.Nanosecond }},
		{name: "excessive timeout", edit: func(c *Config) { c.BusyTimeout = 30*time.Second + time.Nanosecond }},
		{name: "zero readers", edit: func(c *Config) { c.MaxReaders = 0 }},
		{name: "too many readers", edit: func(c *Config) { c.MaxReaders = 65 }},
		{name: "normal synchronous", edit: func(c *Config) { c.Synchronous = "NORMAL" }},
		{name: "empty synchronous", edit: func(c *Config) { c.Synchronous = "" }},
		{name: "too little retention", edit: func(c *Config) { c.ActivationHistoryRetention = 1 }},
		{name: "too much retention", edit: func(c *Config) { c.ActivationHistoryRetention = policyengine.MaxPageResponseItems + 1 }},
		{name: "nil clock", edit: func(c *Config) { c.Clock = nil }},
		{name: "typed nil clock", edit: func(c *Config) { c.Clock = typedNilClock }},
		{name: "missing parent", edit: func(c *Config) { c.Path = missingParent }},
		{name: "file parent", edit: func(c *Config) { c.Path = filepath.Join(parentFile, "policy.db") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig(validPath)
			tc.edit(&config)

			err := config.validate()
			if categoryOf(err) != policyengine.ErrorInvalidArgument {
				t.Fatalf("validate() category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
			}
		})
	}
}

func TestConfigValidateAcceptsBoundedDurableConfiguration(t *testing.T) {
	// This catches an over-broad validator that rejects the documented valid
	// configuration needed to create a durable local SQLite store.
	t.Parallel()

	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.BusyTimeout = 30 * time.Second
	if err := config.validate(); err != nil {
		t.Fatalf("validate() error = %v, want nil", err)
	}
}

func validConfig(path string) Config {
	return Config{
		Path:                       path,
		BusyTimeout:                250 * time.Millisecond,
		MaxReaders:                 2,
		Synchronous:                SynchronousFull,
		ActivationHistoryRetention: 2,
		Clock:                      fixedClock{},
	}
}

func writeTestFile(path string) error {
	return os.WriteFile(path, []byte("x"), 0o600)
}

func categoryOf(err error) policyengine.ErrorCategory {
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok {
		return ""
	}
	return engineErr.Category()
}
