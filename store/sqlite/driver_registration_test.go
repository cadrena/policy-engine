package sqlite_test

import (
	"database/sql"
	"testing"

	_ "github.com/cadrena/policy-engine/store/sqlite"
	_ "modernc.org/sqlite"
)

func TestPolicySQLiteForkAndUpstreamDriverNamesCoexist(t *testing.T) {
	drivers := make(map[string]struct{})
	for _, name := range sql.Drivers() {
		drivers[name] = struct{}{}
	}
	for _, want := range []string{"sqlite", "cadrena-sqlite-nofollow"} {
		if _, ok := drivers[want]; !ok {
			t.Fatalf("registered SQL drivers = %v, want %q", sql.Drivers(), want)
		}
	}
}
