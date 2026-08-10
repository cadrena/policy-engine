package sqlite

import (
	"context"
	"database/sql"
	"strings"

	policyengine "github.com/cadrena/policy-engine"
)

const maxSchemaDDLBytes = 16 << 10

type schemaObjectSpec struct {
	kind  string
	table string
}

type schemaColumnSpec struct {
	name       string
	typ        string
	notNull    int
	primaryKey int
	defaultSet bool
	defaultVal string
}

type schemaForeignKeySpec struct {
	from     string
	table    string
	to       string
	onUpdate string
	onDelete string
}

type schemaIndexColumnSpec struct {
	name       string
	descending bool
}

type schemaIndexSpec struct {
	table   string
	columns []schemaIndexColumnSpec
}

type schemaTableSpec struct {
	columns     []schemaColumnSpec
	checks      []string
	foreignKeys []schemaForeignKeySpec
}

type ddlTokenKind uint8

const (
	ddlTokenWord ddlTokenKind = iota
	ddlTokenQuoted
	ddlTokenSymbol
)

type ddlToken struct {
	kind ddlTokenKind
	text string
}

var schemaV1Objects = map[string]schemaObjectSpec{
	"cadrena_meta":                         {kind: "table", table: "cadrena_meta"},
	"namespace_heads":                      {kind: "table", table: "namespace_heads"},
	"revisions":                            {kind: "table", table: "revisions"},
	"slot_heads":                           {kind: "table", table: "slot_heads"},
	"activation_history":                   {kind: "table", table: "activation_history"},
	"tuples":                               {kind: "table", table: "tuples"},
	"attributes":                           {kind: "table", table: "attributes"},
	"attribute_ancestors":                  {kind: "table", table: "attribute_ancestors"},
	"state_events":                         {kind: "table", table: "state_events"},
	"idempotency_records":                  {kind: "table", table: "idempotency_records"},
	"schema_migrations":                    {kind: "table", table: "schema_migrations"},
	"idx_revisions_namespace_published_at": {kind: "index", table: "revisions"},
	"idx_activation_history_namespace_slot_generation": {kind: "index", table: "activation_history"},
	"idx_tuples_namespace_resource_relation_subject":   {kind: "index", table: "tuples"},
	"idx_tuples_namespace_subject_relation_resource":   {kind: "index", table: "tuples"},
	"idx_attributes_namespace_entity_path":             {kind: "index", table: "attributes"},
	"idx_attribute_ancestors_namespace_ancestor_path":  {kind: "index", table: "attribute_ancestors"},
	"idx_state_events_namespace_sequence":              {kind: "index", table: "state_events"},
}

var schemaV1Tables = map[string]schemaTableSpec{
	"cadrena_meta": {
		columns: []schemaColumnSpec{
			schemaColumn("key", "TEXT", 0, 1),
			schemaColumn("value", "BLOB", 1, 0),
		},
	},
	"namespace_heads": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 0, 1),
			schemaColumnDefault("data_generation", "INTEGER", 1, 0, "0"),
			schemaColumnDefault("event_sequence", "INTEGER", 1, 0, "0"),
			schemaColumnDefault("expired_through", "INTEGER", 1, 0, "0"),
			schemaColumn("effective_time_ns", "INTEGER", 0, 0),
		},
		checks: []string{
			"CHECK (DATA_GENERATION >= 0)",
			"CHECK (EVENT_SEQUENCE >= 0)",
			"CHECK (EXPIRED_THROUGH >= 0)",
		},
	},
	"revisions": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("revision_id", "TEXT", 1, 2),
			schemaColumn("artifact", "BLOB", 1, 0),
			schemaColumn("provenance", "BLOB", 1, 0),
			schemaColumn("published_at_ns", "INTEGER", 1, 0),
		},
	},
	"slot_heads": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("slot", "TEXT", 1, 2),
			schemaColumn("revision_id", "TEXT", 1, 0),
			schemaColumn("generation", "INTEGER", 1, 0),
			schemaColumn("activated_at_ns", "INTEGER", 1, 0),
		},
		checks: []string{"CHECK (GENERATION > 0)"},
		foreignKeys: []schemaForeignKeySpec{
			{from: "namespace", table: "revisions", to: "namespace", onUpdate: "NO ACTION", onDelete: "NO ACTION"},
			{from: "revision_id", table: "revisions", to: "revision_id", onUpdate: "NO ACTION", onDelete: "NO ACTION"},
		},
	},
	"activation_history": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("slot", "TEXT", 1, 2),
			schemaColumn("generation", "INTEGER", 1, 3),
			schemaColumn("revision_id", "TEXT", 1, 0),
			schemaColumn("activated_at_ns", "INTEGER", 1, 0),
		},
		checks: []string{"CHECK (GENERATION > 0)"},
		foreignKeys: []schemaForeignKeySpec{
			{from: "namespace", table: "revisions", to: "namespace", onUpdate: "NO ACTION", onDelete: "NO ACTION"},
			{from: "revision_id", table: "revisions", to: "revision_id", onUpdate: "NO ACTION", onDelete: "NO ACTION"},
		},
	},
	"tuples": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("tuple_key", "BLOB", 1, 2),
			schemaColumn("subject_type", "TEXT", 1, 0),
			schemaColumn("subject_id", "TEXT", 1, 0),
			schemaColumn("subject_relation", "TEXT", 1, 0),
			schemaColumn("relation", "TEXT", 1, 0),
			schemaColumn("resource_type", "TEXT", 1, 0),
			schemaColumn("resource_id", "TEXT", 1, 0),
			schemaColumn("expires_at_ns", "INTEGER", 0, 0),
		},
	},
	"attributes": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("attribute_key", "BLOB", 1, 2),
			schemaColumn("entity_type", "TEXT", 1, 0),
			schemaColumn("entity_id", "TEXT", 1, 0),
			schemaColumn("path", "BLOB", 1, 0),
			schemaColumn("value", "BLOB", 1, 0),
			schemaColumn("expires_at_ns", "INTEGER", 0, 0),
		},
	},
	"attribute_ancestors": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("attribute_key", "BLOB", 1, 2),
			schemaColumn("ancestor_path", "BLOB", 1, 3),
		},
		foreignKeys: []schemaForeignKeySpec{
			{from: "namespace", table: "attributes", to: "namespace", onUpdate: "NO ACTION", onDelete: "CASCADE"},
			{from: "attribute_key", table: "attributes", to: "attribute_key", onUpdate: "NO ACTION", onDelete: "CASCADE"},
		},
	},
	"state_events": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("sequence", "INTEGER", 1, 2),
			schemaColumn("kind", "TEXT", 1, 0),
			schemaColumn("payload", "BLOB", 1, 0),
			schemaColumn("created_at_ns", "INTEGER", 1, 0),
		},
		checks: []string{"CHECK (SEQUENCE > 0)"},
	},
	"idempotency_records": {
		columns: []schemaColumnSpec{
			schemaColumn("namespace", "TEXT", 1, 1),
			schemaColumn("idempotency_key", "TEXT", 1, 2),
			schemaColumn("fingerprint", "BLOB", 1, 0),
			schemaColumn("response", "BLOB", 1, 0),
		},
	},
}

var schemaV1Indexes = map[string]schemaIndexSpec{
	"idx_revisions_namespace_published_at": {
		table: "revisions",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "published_at_ns", descending: true}, {name: "revision_id"},
		},
	},
	"idx_activation_history_namespace_slot_generation": {
		table: "activation_history",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "slot"}, {name: "generation", descending: true},
		},
	},
	"idx_tuples_namespace_resource_relation_subject": {
		table: "tuples",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "resource_type"}, {name: "resource_id"}, {name: "relation"}, {name: "subject_type"}, {name: "subject_id"}, {name: "subject_relation"},
		},
	},
	"idx_tuples_namespace_subject_relation_resource": {
		table: "tuples",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "subject_type"}, {name: "subject_id"}, {name: "subject_relation"}, {name: "relation"}, {name: "resource_type"}, {name: "resource_id"},
		},
	},
	"idx_attributes_namespace_entity_path": {
		table: "attributes",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "entity_type"}, {name: "entity_id"}, {name: "path"},
		},
	},
	"idx_attribute_ancestors_namespace_ancestor_path": {
		table: "attribute_ancestors",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "ancestor_path"}, {name: "attribute_key"},
		},
	},
	"idx_state_events_namespace_sequence": {
		table: "state_events",
		columns: []schemaIndexColumnSpec{
			{name: "namespace"}, {name: "sequence"},
		},
	},
}

func schemaColumn(name, typ string, notNull, primaryKey int) schemaColumnSpec {
	return schemaColumnSpec{name: name, typ: typ, notNull: notNull, primaryKey: primaryKey}
}

func schemaColumnDefault(name, typ string, notNull, primaryKey int, defaultVal string) schemaColumnSpec {
	return schemaColumnSpec{name: name, typ: typ, notNull: notNull, primaryKey: primaryKey, defaultSet: true, defaultVal: defaultVal}
}

func validateSchemaV1(ctx context.Context, conn *sql.Conn) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	objects, err := readSchemaObjects(ctx, conn)
	if err != nil {
		return err
	}
	if len(objects) != len(schemaV1Objects) {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	for name, expected := range schemaV1Objects {
		if got, ok := objects[name]; !ok || got != expected {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	for name, expected := range schemaV1Tables {
		if err := validateTable(ctx, conn, name, expected); err != nil {
			return err
		}
	}
	for name, expected := range schemaV1Indexes {
		if err := validateIndex(ctx, conn, name, expected); err != nil {
			return err
		}
	}
	return nil
}

func readSchemaObjects(ctx context.Context, conn *sql.Conn) (map[string]schemaObjectSpec, error) {
	rows, err := conn.QueryContext(ctx, "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index', 'view', 'trigger') AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?", len(schemaV1Objects)+1)
	if err != nil {
		return nil, schemaValidationError(ctx, err)
	}
	defer rows.Close()
	objects := make(map[string]schemaObjectSpec, len(schemaV1Objects))
	for rows.Next() {
		if len(objects) >= len(schemaV1Objects) {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		var kind, name, table string
		if err := rows.Scan(&kind, &name, &table); err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		objects[name] = schemaObjectSpec{kind: kind, table: table}
	}
	if err := rows.Err(); err != nil {
		return nil, schemaValidationError(ctx, err)
	}
	return objects, nil
}

func validateTable(ctx context.Context, conn *sql.Conn, table string, expected schemaTableSpec) error {
	if err := validateTableColumns(ctx, conn, table, expected.columns); err != nil {
		return err
	}
	if err := validateTableChecks(ctx, conn, table, expected.checks); err != nil {
		return err
	}
	return validateTableForeignKeys(ctx, conn, table, expected.foreignKeys)
}

func validateTableColumns(ctx context.Context, conn *sql.Conn, table string, expected []schemaColumnSpec) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return schemaValidationError(ctx, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if count >= len(expected) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		var cid, notNull, primaryKey int
		var name, typ string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		want := expected[count]
		if cid != count || name != want.name || strings.ToUpper(typ) != want.typ || notNull != want.notNull || primaryKey != want.primaryKey || defaultValue.Valid != want.defaultSet || (defaultValue.Valid && defaultValue.String != want.defaultVal) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return schemaValidationError(ctx, err)
	}
	if count != len(expected) {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func validateTableChecks(ctx context.Context, conn *sql.Conn, table string, checks []string) error {
	var ddl string
	err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? AND length(sql) <= ?", table, maxSchemaDDLBytes).Scan(&ddl)
	if err != nil {
		return schemaValidationError(ctx, err)
	}
	tokens, err := canonicalDDLTokens(ddl)
	if err != nil {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	for _, check := range checks {
		expression, ok := canonicalCheckExpression(check)
		if !ok || !containsCanonicalCheck(tokens, expression) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

func canonicalDDLTokens(ddl string) ([]ddlToken, error) {
	tokens := make([]ddlToken, 0, len(ddl)/4)
	for index := 0; index < len(ddl); {
		switch {
		case isSQLiteSpace(ddl[index]):
			index++
		case hasPrefixAt(ddl, index, "--"):
			index = skipSQLiteLineComment(ddl, index+2)
		case hasPrefixAt(ddl, index, "/*"):
			end := strings.Index(ddl[index+2:], "*/")
			if end < 0 {
				return nil, sqliteError(policyengine.ErrorIntegrity)
			}
			index += end + 4
		case ddl[index] == '\'' || ddl[index] == '"' || ddl[index] == '`':
			end, ok := skipSQLiteDelimitedToken(ddl, index, ddl[index])
			if !ok {
				return nil, sqliteError(policyengine.ErrorIntegrity)
			}
			tokens = append(tokens, ddlToken{kind: ddlTokenQuoted})
			index = end
		case ddl[index] == '[':
			end, ok := skipSQLiteBracketIdentifier(ddl, index)
			if !ok {
				return nil, sqliteError(policyengine.ErrorIntegrity)
			}
			tokens = append(tokens, ddlToken{kind: ddlTokenQuoted})
			index = end
		case isSQLiteBareTokenByte(ddl[index]):
			end := index + 1
			for end < len(ddl) && isSQLiteBareTokenByte(ddl[end]) {
				end++
			}
			tokens = append(tokens, ddlToken{kind: ddlTokenWord, text: strings.ToUpper(ddl[index:end])})
			index = end
		default:
			width := 1
			if index+1 < len(ddl) && isSQLiteTwoByteOperator(ddl[index:index+2]) {
				width = 2
			}
			tokens = append(tokens, ddlToken{kind: ddlTokenSymbol, text: ddl[index : index+width]})
			index += width
		}
	}
	return tokens, nil
}

func canonicalCheckExpression(check string) ([]ddlToken, bool) {
	tokens, err := canonicalDDLTokens(check)
	if err != nil || len(tokens) < 4 || !isDDLWord(tokens[0], "CHECK") || !isDDLSymbol(tokens[1], "(") {
		return nil, false
	}
	end, ok := matchingDDLParenthesis(tokens, 1)
	if !ok || end != len(tokens)-1 || end == 2 {
		return nil, false
	}
	return tokens[2:end], true
}

func containsCanonicalCheck(tokens, expression []ddlToken) bool {
	for index := 0; index+2 < len(tokens); index++ {
		if !isDDLWord(tokens[index], "CHECK") || !isDDLSymbol(tokens[index+1], "(") {
			continue
		}
		end, ok := matchingDDLParenthesis(tokens, index+1)
		if !ok {
			return false
		}
		if equalDDLTokenSlices(tokens[index+2:end], expression) {
			return true
		}
	}
	return false
}

func matchingDDLParenthesis(tokens []ddlToken, open int) (int, bool) {
	depth := 0
	for index := open; index < len(tokens); index++ {
		switch {
		case isDDLSymbol(tokens[index], "("):
			depth++
		case isDDLSymbol(tokens[index], ")"):
			depth--
			if depth == 0 {
				return index, true
			}
			if depth < 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func equalDDLTokenSlices(left, right []ddlToken) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func isDDLWord(token ddlToken, word string) bool {
	return token.kind == ddlTokenWord && token.text == word
}

func isDDLSymbol(token ddlToken, symbol string) bool {
	return token.kind == ddlTokenSymbol && token.text == symbol
}

func isSQLiteSpace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func hasPrefixAt(value string, index int, prefix string) bool {
	return len(value)-index >= len(prefix) && value[index:index+len(prefix)] == prefix
}

func skipSQLiteLineComment(value string, index int) int {
	for index < len(value) && value[index] != '\n' && value[index] != '\r' {
		index++
	}
	return index
}

func skipSQLiteDelimitedToken(value string, index int, delimiter byte) (int, bool) {
	for index++; index < len(value); index++ {
		if value[index] != delimiter {
			continue
		}
		if index+1 < len(value) && value[index+1] == delimiter {
			index++
			continue
		}
		return index + 1, true
	}
	return 0, false
}

func skipSQLiteBracketIdentifier(value string, index int) (int, bool) {
	for index++; index < len(value); index++ {
		if value[index] != ']' {
			continue
		}
		if index+1 < len(value) && value[index+1] == ']' {
			index++
			continue
		}
		return index + 1, true
	}
	return 0, false
}

func isSQLiteBareTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '$' || value >= 0x80
}

func isSQLiteTwoByteOperator(value string) bool {
	switch value {
	case ">=", "<=", "<>", "!=", "==", "||", "<<", ">>":
		return true
	default:
		return false
	}
}

func validateTableForeignKeys(ctx context.Context, conn *sql.Conn, table string, expected []schemaForeignKeySpec) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_list("+table+")")
	if err != nil {
		return schemaValidationError(ctx, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if count >= len(expected) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		var id, sequence int
		var parent, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &sequence, &parent, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		want := expected[count]
		if id != 0 || sequence != count || from != want.from || parent != want.table || to != want.to || onUpdate != want.onUpdate || onDelete != want.onDelete || match != "NONE" {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return schemaValidationError(ctx, err)
	}
	if count != len(expected) {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func validateIndex(ctx context.Context, conn *sql.Conn, name string, expected schemaIndexSpec) error {
	if err := validateIndexDefinition(ctx, conn, name, expected.table); err != nil {
		return err
	}
	rows, err := conn.QueryContext(ctx, "PRAGMA index_xinfo("+name+")")
	if err != nil {
		return schemaValidationError(ctx, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var sequence, columnID, descending, key int
		var column sql.NullString
		var collation string
		if err := rows.Scan(&sequence, &columnID, &column, &descending, &collation, &key); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if key == 0 {
			continue
		}
		if count >= len(expected.columns) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		want := expected.columns[count]
		if sequence != count || !column.Valid || column.String != want.name || (descending != 0) != want.descending || collation != "BINARY" {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return schemaValidationError(ctx, err)
	}
	if count != len(expected.columns) {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func validateIndexDefinition(ctx context.Context, conn *sql.Conn, name, table string) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA index_list("+table+")")
	if err != nil {
		return schemaValidationError(ctx, err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var sequence, unique, partial int
		var indexName, origin string
		if err := rows.Scan(&sequence, &indexName, &unique, &origin, &partial); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if indexName == name {
			if unique != 0 || origin != "c" || partial != 0 {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return schemaValidationError(ctx, err)
	}
	if !found {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func schemaValidationError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if err == nil {
		return nil
	}
	return sqliteError(policyengine.ErrorIntegrity)
}
