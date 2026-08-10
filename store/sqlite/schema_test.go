package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func TestMigrationInitialSchemaContainsRequiredTablesIndexesForeignKeysAndChecks(t *testing.T) {
	// This catches a migration that reaches version 1 but omits a normalized
	// table, required query index, referential edge, or bounded counter check.
	path := filepath.Join(t.TempDir(), "policy.db")
	if _, err := ApplyMigrations(context.Background(), validConfig(path)); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)

	wantObjects := map[string]schemaObjectForTest{
		"cadrena_meta":                         {objectType: "table", table: "cadrena_meta"},
		"namespace_heads":                      {objectType: "table", table: "namespace_heads"},
		"revisions":                            {objectType: "table", table: "revisions"},
		"slot_heads":                           {objectType: "table", table: "slot_heads"},
		"activation_history":                   {objectType: "table", table: "activation_history"},
		"tuples":                               {objectType: "table", table: "tuples"},
		"attributes":                           {objectType: "table", table: "attributes"},
		"attribute_ancestors":                  {objectType: "table", table: "attribute_ancestors"},
		"state_events":                         {objectType: "table", table: "state_events"},
		"idempotency_records":                  {objectType: "table", table: "idempotency_records"},
		"schema_migrations":                    {objectType: "table", table: "schema_migrations"},
		"idx_revisions_namespace_published_at": {objectType: "index", table: "revisions"},
		"idx_activation_history_namespace_slot_generation": {objectType: "index", table: "activation_history"},
		"idx_tuples_namespace_resource_relation_subject":   {objectType: "index", table: "tuples"},
		"idx_tuples_namespace_subject_relation_resource":   {objectType: "index", table: "tuples"},
		"idx_attributes_namespace_entity_path":             {objectType: "index", table: "attributes"},
		"idx_attribute_ancestors_namespace_ancestor_path":  {objectType: "index", table: "attribute_ancestors"},
		"idx_state_events_namespace_sequence":              {objectType: "index", table: "state_events"},
	}
	gotObjects := schemaObjectsForTest(t, db)
	if !maps.Equal(gotObjects, wantObjects) {
		t.Fatalf("schema objects = %#v, want %#v", gotObjects, wantObjects)
	}

	for _, tc := range []struct {
		table  string
		checks []string
	}{
		{table: "namespace_heads", checks: []string{
			"CHECK (DATA_GENERATION >= 0)",
			"CHECK (EVENT_SEQUENCE >= 0)",
			"CHECK (EXPIRED_THROUGH >= 0)",
		}},
		{table: "slot_heads", checks: []string{"CHECK (GENERATION > 0)"}},
		{table: "activation_history", checks: []string{"CHECK (GENERATION > 0)"}},
		{table: "state_events", checks: []string{"CHECK (SEQUENCE > 0)"}},
	} {
		ddl := normalizedDDLForTest(t, db, tc.table)
		for _, check := range tc.checks {
			if !strings.Contains(ddl, check) {
				t.Fatalf("%s DDL %q does not contain %q", tc.table, ddl, check)
			}
		}
	}

	for _, tc := range []struct {
		table string
		want  []string
	}{
		{
			table: "slot_heads",
			want: []string{
				"0|0|revisions|namespace|namespace|NO ACTION|NO ACTION",
				"0|1|revisions|revision_id|revision_id|NO ACTION|NO ACTION",
			},
		},
		{
			table: "activation_history",
			want: []string{
				"0|0|revisions|namespace|namespace|NO ACTION|NO ACTION",
				"0|1|revisions|revision_id|revision_id|NO ACTION|NO ACTION",
			},
		},
		{
			table: "attribute_ancestors",
			want: []string{
				"0|0|attributes|namespace|namespace|NO ACTION|CASCADE",
				"0|1|attributes|attribute_key|attribute_key|NO ACTION|CASCADE",
			},
		},
	} {
		if got := foreignKeysForTest(t, db, tc.table); !slices.Equal(got, tc.want) {
			t.Fatalf("%s foreign keys = %q, want %q", tc.table, got, tc.want)
		}
	}

	for _, tc := range []struct {
		name string
		want []indexColumnForTest
	}{
		{
			name: "idx_revisions_namespace_published_at",
			want: []indexColumnForTest{{"namespace", false}, {"published_at_ns", true}, {"revision_id", false}},
		},
		{
			name: "idx_activation_history_namespace_slot_generation",
			want: []indexColumnForTest{{"namespace", false}, {"slot", false}, {"generation", true}},
		},
		{
			name: "idx_tuples_namespace_resource_relation_subject",
			want: []indexColumnForTest{{"namespace", false}, {"resource_type", false}, {"resource_id", false}, {"relation", false}, {"subject_type", false}, {"subject_id", false}, {"subject_relation", false}},
		},
		{
			name: "idx_tuples_namespace_subject_relation_resource",
			want: []indexColumnForTest{{"namespace", false}, {"subject_type", false}, {"subject_id", false}, {"subject_relation", false}, {"relation", false}, {"resource_type", false}, {"resource_id", false}},
		},
		{
			name: "idx_attributes_namespace_entity_path",
			want: []indexColumnForTest{{"namespace", false}, {"entity_type", false}, {"entity_id", false}, {"path", false}},
		},
		{
			name: "idx_attribute_ancestors_namespace_ancestor_path",
			want: []indexColumnForTest{{"namespace", false}, {"ancestor_path", false}, {"attribute_key", false}},
		},
		{
			name: "idx_state_events_namespace_sequence",
			want: []indexColumnForTest{{"namespace", false}, {"sequence", false}},
		},
	} {
		if got := indexColumnsForTest(t, db, tc.name); !slices.Equal(got, tc.want) {
			t.Fatalf("%s columns = %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

func TestValidateSchemaRejectsMissingRequiredIndex(t *testing.T) {
	// This catches validation that checks only the migration ledger and misses a
	// damaged schema which can silently break the bounded query plan contract.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)
	mustExecMigrationTest(t, db, "DROP INDEX idx_tuples_namespace_subject_relation_resource")
	if err := db.Close(); err != nil {
		t.Fatalf("close damaged database: %v", err)
	}

	if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
}

func TestValidateSchemaRejectsRequiredCheckTextOnlyInComments(t *testing.T) {
	// This catches a validator that searches stored DDL text: SQLite preserves
	// comments, so a fake CHECK inside one must not satisfy a real constraint.
	for _, comment := range []struct {
		name string
		text string
	}{
		{name: "block comment", text: "/* CHECK (GENERATION > 0) */"},
		{name: "line comment", text: "-- CHECK (GENERATION > 0)"},
	} {
		t.Run(comment.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.db")
			config := validConfig(path)
			if _, err := ApplyMigrations(context.Background(), config); err != nil {
				t.Fatalf("ApplyMigrations() error = %v", err)
			}
			db := openRawSQLite(t, path)
			mustExecMigrationTest(t, db, "DROP TABLE slot_heads")
			mustExecMigrationTest(t, db, "CREATE TABLE slot_heads (\n"+
				"namespace TEXT NOT NULL,\n"+
				"slot TEXT NOT NULL,\n"+
				"revision_id TEXT NOT NULL,\n"+
				"generation INTEGER NOT NULL, "+comment.text+"\n"+
				"activated_at_ns INTEGER NOT NULL,\n"+
				"PRIMARY KEY (namespace, slot),\n"+
				"FOREIGN KEY (namespace, revision_id) REFERENCES revisions(namespace, revision_id)\n"+
				")")
			if err := db.Close(); err != nil {
				t.Fatalf("close damaged database: %v", err)
			}

			if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
				t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestValidateSchemaRejectsRequiredCheckTextOnlyInQuotedConstraintName(t *testing.T) {
	// This catches a normalizer that turns quoted identifier content into SQL
	// keywords, treating a constraint name as the required CHECK expression.
	for _, quote := range []struct {
		name string
		text string
	}{
		{name: "double quote", text: "\"CHECK (GENERATION > 0)\""},
		{name: "single quote", text: "'CHECK (GENERATION > 0)'"},
		{name: "backtick", text: "`CHECK (GENERATION > 0)`"},
		{name: "bracket", text: "[CHECK (GENERATION > 0)]"},
	} {
		t.Run(quote.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.db")
			config := validConfig(path)
			if _, err := ApplyMigrations(context.Background(), config); err != nil {
				t.Fatalf("ApplyMigrations() error = %v", err)
			}
			db := openRawSQLite(t, path)
			mustExecMigrationTest(t, db, "DROP TABLE slot_heads")
			mustExecMigrationTest(t, db, "CREATE TABLE slot_heads (\n"+
				"namespace TEXT NOT NULL,\n"+
				"slot TEXT NOT NULL,\n"+
				"revision_id TEXT NOT NULL,\n"+
				"generation INTEGER NOT NULL,\n"+
				"activated_at_ns INTEGER NOT NULL,\n"+
				"PRIMARY KEY (namespace, slot),\n"+
				"FOREIGN KEY (namespace, revision_id) REFERENCES revisions(namespace, revision_id),\n"+
				"CONSTRAINT "+quote.text+" UNIQUE (namespace, slot)\n"+
				")")
			if err := db.Close(); err != nil {
				t.Fatalf("close damaged database: %v", err)
			}

			if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
				t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestValidateSchemaRejectsAlteredRequiredCheck(t *testing.T) {
	// This catches accepting a superficially similar check whose weakened
	// operator changes the required positive-generation invariant.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)
	mustExecMigrationTest(t, db, "DROP TABLE slot_heads")
	mustExecMigrationTest(t, db, "CREATE TABLE slot_heads (\n"+
		"namespace TEXT NOT NULL,\n"+
		"slot TEXT NOT NULL,\n"+
		"revision_id TEXT NOT NULL,\n"+
		"generation INTEGER NOT NULL CHECK (generation >= 0),\n"+
		"activated_at_ns INTEGER NOT NULL,\n"+
		"PRIMARY KEY (namespace, slot),\n"+
		"FOREIGN KEY (namespace, revision_id) REFERENCES revisions(namespace, revision_id)\n"+
		")")
	if err := db.Close(); err != nil {
		t.Fatalf("close damaged database: %v", err)
	}

	if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
}

type schemaObjectForTest struct {
	objectType string
	table      string
}

type indexColumnForTest struct {
	name       string
	descending bool
}

func schemaObjectsForTest(t *testing.T, db *sql.DB) map[string]schemaObjectForTest {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		t.Fatalf("query schema objects: %v", err)
	}
	defer rows.Close()
	objects := make(map[string]schemaObjectForTest)
	for rows.Next() {
		var object schemaObjectForTest
		var name string
		if err := rows.Scan(&object.objectType, &name, &object.table); err != nil {
			t.Fatalf("scan schema object: %v", err)
		}
		objects[name] = object
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema objects: %v", err)
	}
	return objects
}

func normalizedDDLForTest(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	var ddl string
	if err := db.QueryRowContext(context.Background(), "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&ddl); err != nil {
		t.Fatalf("read %s DDL: %v", table, err)
	}
	return strings.Join(strings.Fields(strings.ToUpper(ddl)), " ")
}

func foreignKeysForTest(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "PRAGMA foreign_key_list("+table+")")
	if err != nil {
		t.Fatalf("read %s foreign keys: %v", table, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, sequence int
		var parent, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &sequence, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan %s foreign key: %v", table, err)
		}
		got = append(got, fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s", id, sequence, parent, from, to, onUpdate, onDelete))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s foreign keys: %v", table, err)
	}
	return got
}

func indexColumnsForTest(t *testing.T, db *sql.DB, index string) []indexColumnForTest {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "PRAGMA index_xinfo("+index+")")
	if err != nil {
		t.Fatalf("read %s index columns: %v", index, err)
	}
	defer rows.Close()
	var got []indexColumnForTest
	for rows.Next() {
		var sequence, columnID, descending, key int
		var name sql.NullString
		var collation string
		if err := rows.Scan(&sequence, &columnID, &name, &descending, &collation, &key); err != nil {
			t.Fatalf("scan %s index column: %v", index, err)
		}
		if key == 1 {
			got = append(got, indexColumnForTest{name: name.String, descending: descending != 0})
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s index columns: %v", index, err)
	}
	return got
}
