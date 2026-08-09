// Package sqlite provides the durable SQLite storage foundation.
package sqlite

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

const (
	maxBusyTimeout = 30 * time.Second
	maxReaders     = 64
)

// SynchronousMode controls SQLite's synchronous durability setting.
type SynchronousMode string

const (
	// SynchronousFull requires SQLite's fully durable synchronous setting.
	SynchronousFull SynchronousMode = "FULL"
)

// Clock supplies timestamps for durable store records.
type Clock interface {
	Now() time.Time
}

// Config configures a durable local SQLite store.
//
// Every value is explicit. In particular, callers must provide a positive
// BusyTimeout; the package does not silently select one.
type Config struct {
	Path                       string
	BusyTimeout                time.Duration
	MaxReaders                 int
	Synchronous                SynchronousMode
	ActivationHistoryRetention int
	Clock                      Clock
}

func (c Config) validate() error {
	if !durablePath(c.Path) ||
		c.BusyTimeout <= 0 || c.BusyTimeout > maxBusyTimeout || c.BusyTimeout%time.Millisecond != 0 ||
		c.MaxReaders < 1 || c.MaxReaders > maxReaders ||
		c.Synchronous != SynchronousFull ||
		c.ActivationHistoryRetention < 2 || c.ActivationHistoryRetention > policyengine.MaxPageResponseItems ||
		isNilClock(c.Clock) {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	return nil
}

func durablePath(path string) bool {
	if path == "" || strings.EqualFold(path, ":memory:") || strings.HasPrefix(strings.ToLower(path), "file:") || !filepath.IsAbs(path) {
		return false
	}

	parent, err := os.Stat(filepath.Dir(path))
	return err == nil && parent.IsDir()
}

func isNilClock(clock Clock) bool {
	if clock == nil {
		return true
	}
	v := reflect.ValueOf(clock)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
