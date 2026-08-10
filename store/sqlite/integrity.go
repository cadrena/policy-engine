package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
	"github.com/cadrena/policy-engine/store"
)

// FullIntegrityCheck verifies every durable record without repairing,
// migrating, checkpointing, or opening a runtime Store. It is intentionally an
// exclusive offline operation: a compatible runtime or maintenance process
// receives UNAVAILABLE instead of sharing a mutable database view.
func FullIntegrityCheck(ctx context.Context, config Config) (err error) {
	return fullIntegrityCheckWithConnectorFactory(ctx, config, moderncsqlite.NewConnector)
}

// fullIntegrityCheckWithConnectorFactory keeps the offline checker on the
// same physical connection path as production while allowing deterministic
// connector-boundary checks of the default SQLite VFS.
func fullIntegrityCheckWithConnectorFactory(ctx context.Context, config Config, newConnector connectorFactory) (err error) {
	if newConnector == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	config, err = validateMigrationRequest(ctx, config)
	if err != nil {
		return err
	}
	exists, err := sqliteDatabaseExists(config.Path)
	if err != nil {
		return mapError(ctx, err)
	}
	if !exists {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := lockIntegrityExclusive(ctx, lock, config.BusyTimeout); err != nil {
		return err
	}
	exists, err = sqliteDatabaseExists(config.Path)
	if err != nil {
		return mapError(ctx, err)
	}
	if !exists {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := validateWALFile(ctx, config.Path); err != nil {
		return integrityResultError(ctx, err)
	}

	database, conn, err := openExistingIntegrityConnectionWithConnectorFactory(ctx, config, newConnector)
	if err != nil {
		return integrityResultError(ctx, err)
	}
	defer closeMigrationConnection(database, conn)
	if err := persistIntegrityWAL(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := verifyConnectionPragmas(ctx, conn, config, false); err != nil {
		return integrityResultError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	defer func() {
		_ = rollbackMigration(conn)
	}()
	// Revalidate after SQLite has excluded independent writers. The preflight
	// above prevents SQLite from interpreting a malformed sidecar while opening;
	// this locked pass binds the complete scan to the exact WAL bytes it reads.
	if err := validateWALFile(ctx, config.Path); err != nil {
		return integrityResultError(ctx, err)
	}

	if err := fullIntegrityCheck(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	return nil
}

// validateRuntimeState keeps public Open bounded to schema, ledger, connection,
// metadata, and namespace-head state. It deliberately does not scan artifacts,
// tuples, attributes, events, or idempotency rows; FullIntegrityCheck owns that
// offline work.
func validateRuntimeState(ctx context.Context, database *database) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if database == nil || database.readers == nil {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	release, err := database.acquireReader(ctx)
	if err != nil {
		return err
	}
	defer release()
	conn, err := database.readers.Conn(ctx)
	if err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	defer func() { _ = conn.Close() }()

	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return integrityResultError(ctx, err)
	}
	ledger, err := readMigrationLedger(ctx, conn, migrations)
	if err != nil {
		return integrityResultError(ctx, err)
	}
	if !ledger.exists || ledger.current != uint64(len(migrations)) {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := verifyConnectionPragmas(ctx, conn, database.config, true); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := validateSchemaV1(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	if _, err := readCursorKey(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	return validateRuntimeNamespaceHeads(ctx, conn)
}

func lockIntegrityExclusive(ctx context.Context, lock advisoryLock, timeout time.Duration) error {
	if lock == nil {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	lockContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := lock.LockExclusive(lockContext); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		if categoryOfIntegrityError(err) == policyengine.ErrorDeadlineExceeded {
			return sqliteError(policyengine.ErrorUnavailable)
		}
		return err
	}
	return nil
}

func openExistingIntegrityConnectionWithConnectorFactory(ctx context.Context, config Config, newConnector connectorFactory) (*sql.DB, *sql.Conn, error) {
	if newConnector == nil {
		return nil, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	connector, err := newConnector(integrityDSN(config))
	if err != nil {
		return nil, nil, mapError(ctx, err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	conn, err := database.Conn(ctx)
	if err != nil {
		_ = database.Close()
		return nil, nil, mapError(ctx, err)
	}
	return database, conn, nil
}

// persistIntegrityWAL prevents the checker connection's final close from
// checkpointing or deleting a hot WAL that it merely inspected. The setting is
// deliberately not reset: resetting it on the final connection can perform the
// very close-time cleanup this offline checker is forbidden to cause.
func persistIntegrityWAL(ctx context.Context, conn *sql.Conn) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if conn == nil {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return conn.Raw(func(driverConn any) error {
		controller, ok := driverConn.(moderncsqlite.FileControl)
		if !ok {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		mode, err := controller.FileControlPersistWAL("main", 1)
		if err != nil {
			return err
		}
		if mode != 1 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		return nil
	})
}

// integrityDSN deliberately omits _journal_mode. An integrity check must
// observe a non-WAL database as invalid instead of promoting it to WAL while
// merely inspecting the durable state.
func integrityDSN(config Config) string {
	uri := &url.URL{Scheme: "file", Path: config.Path}
	query := url.Values{}
	query.Set("mode", "rw")
	query.Set("_busy_timeout", strconv.FormatInt(config.BusyTimeout.Milliseconds(), 10))
	query.Set("_foreign_keys", "on")
	query.Set("_synchronous", string(config.Synchronous))
	uri.RawQuery = query.Encode()
	return uri.String()
}

const (
	sqliteDatabaseHeaderBytes = 100
	sqliteWALHeaderBytes      = 32
	sqliteWALFrameHeaderBytes = 24
	sqliteWALMagicLittle      = 0x377f0682
	sqliteWALMagicBig         = 0x377f0683
	sqliteWALFormatVersion    = 3007000
)

// validateRuntimeWALState performs the bounded physical check needed before a
// runtime opens SQLite. SQLite can otherwise ignore a malformed sidecar as an
// empty WAL. The offline checker below additionally verifies every frame.
func validateRuntimeWALState(ctx context.Context, databasePath string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	wal, err := os.Open(databasePath + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = wal.Close() }()
	info, err := wal.Stat()
	if err != nil {
		return mapError(ctx, err)
	}
	if !info.Mode().IsRegular() {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	if info.Size() == 0 {
		return nil
	}
	if info.Size() < sqliteWALHeaderBytes {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	pageSize, err := sqliteDatabasePageSize(ctx, databasePath)
	if err != nil {
		return err
	}
	var header [sqliteWALHeaderBytes]byte
	if _, err := io.ReadFull(wal, header[:]); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if _, err := sqliteWALHeaderByteOrder(header[:], pageSize); err != nil {
		return err
	}
	frameBytes := sqliteWALFrameHeaderBytes + pageSize
	if (info.Size()-sqliteWALHeaderBytes)%int64(frameBytes) != 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

// validateWALFile rejects a malformed hot WAL before SQLite has an opportunity
// to interpret a damaged header as an ignorable stale sidecar. It streams one
// frame at a time and verifies the documented header/frame checksum chain; it
// never opens a SQLite connection or changes any durable file.
func validateWALFile(ctx context.Context, databasePath string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	walPath := databasePath + "-wal"
	wal, err := os.Open(walPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = wal.Close() }()
	info, err := wal.Stat()
	if err != nil {
		return mapError(ctx, err)
	}
	if !info.Mode().IsRegular() {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	// SQLite may leave an empty -wal sidecar behind after opening a database
	// without committing WAL frames. It contains no recovery state, so only a
	// non-empty sidecar needs to carry the fixed WAL header.
	if info.Size() == 0 {
		return nil
	}
	if info.Size() < sqliteWALHeaderBytes {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	pageSize, err := sqliteDatabasePageSize(ctx, databasePath)
	if err != nil {
		return err
	}
	var header [sqliteWALHeaderBytes]byte
	if _, err := io.ReadFull(wal, header[:]); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	order, err := sqliteWALHeaderByteOrder(header[:], pageSize)
	if err != nil {
		return err
	}
	checksumOne, checksumTwo := sqliteWALChecksum(header[:24], order, 0, 0)
	frameBytes := sqliteWALFrameHeaderBytes + pageSize
	if (info.Size()-sqliteWALHeaderBytes)%int64(frameBytes) != 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	frame := make([]byte, frameBytes)
	for offset := int64(sqliteWALHeaderBytes); offset < info.Size(); offset += int64(frameBytes) {
		if err := contextError(ctx); err != nil {
			return err
		}
		if _, err := io.ReadFull(wal, frame); err != nil {
			return integrityResultError(ctx, mapError(ctx, err))
		}
		if binary.BigEndian.Uint32(frame[0:4]) == 0 || !bytes.Equal(frame[8:16], header[16:24]) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		checksumOne, checksumTwo = sqliteWALChecksum(frame[0:8], order, checksumOne, checksumTwo)
		checksumOne, checksumTwo = sqliteWALChecksum(frame[sqliteWALFrameHeaderBytes:], order, checksumOne, checksumTwo)
		if binary.BigEndian.Uint32(frame[16:20]) != checksumOne || binary.BigEndian.Uint32(frame[20:24]) != checksumTwo {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

func sqliteDatabasePageSize(ctx context.Context, path string) (int, error) {
	database, err := os.Open(path)
	if err != nil {
		return 0, mapError(ctx, err)
	}
	defer func() { _ = database.Close() }()
	var header [sqliteDatabaseHeaderBytes]byte
	if _, err := io.ReadFull(database, header[:]); err != nil {
		return 0, integrityResultError(ctx, mapError(ctx, err))
	}
	if string(header[:16]) != "SQLite format 3\x00" || header[18] != 2 || header[19] != 2 {
		return 0, sqliteError(policyengine.ErrorIntegrity)
	}
	pageSize := int(binary.BigEndian.Uint16(header[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 0, sqliteError(policyengine.ErrorIntegrity)
	}
	return pageSize, nil
}

func sqliteWALChecksum(data []byte, order binary.ByteOrder, first, second uint32) (uint32, uint32) {
	for index := 0; index < len(data); index += 8 {
		first += order.Uint32(data[index:index+4]) + second
		second += order.Uint32(data[index+4:index+8]) + first
	}
	return first, second
}

func sqliteWALHeaderByteOrder(header []byte, pageSize int) (binary.ByteOrder, error) {
	if len(header) != sqliteWALHeaderBytes {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	var order binary.ByteOrder
	switch magic {
	case sqliteWALMagicLittle:
		order = binary.LittleEndian
	case sqliteWALMagicBig:
		order = binary.BigEndian
	default:
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	if binary.BigEndian.Uint32(header[4:8]) != sqliteWALFormatVersion || int(binary.BigEndian.Uint32(header[8:12])) != pageSize {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	checksumOne, checksumTwo := sqliteWALChecksum(header[:24], order, 0, 0)
	if binary.BigEndian.Uint32(header[24:28]) != checksumOne || binary.BigEndian.Uint32(header[28:32]) != checksumTwo {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	return order, nil
}

func fullIntegrityCheck(ctx context.Context, conn *sql.Conn) error {
	if err := runSQLiteIntegrityCheck(ctx, conn); err != nil {
		return err
	}
	if err := runSQLiteForeignKeyCheck(ctx, conn); err != nil {
		return err
	}
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return err
	}
	ledger, err := readMigrationLedger(ctx, conn, migrations)
	if err != nil {
		return err
	}
	if !ledger.exists || ledger.current != uint64(len(migrations)) {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := validateSchemaV1(ctx, conn); err != nil {
		return err
	}
	key, err := readCursorKey(ctx, conn)
	if err != nil {
		return err
	}
	if err := validateFullValueBounds(ctx, conn); err != nil {
		return err
	}
	heads, err := validateFullNamespaceHeads(ctx, conn)
	if err != nil {
		return err
	}
	revisions, err := validateFullRevisions(ctx, conn, heads)
	if err != nil {
		return err
	}
	history, err := validateFullActivationHistory(ctx, conn, heads, revisions)
	if err != nil {
		return err
	}
	slots, err := validateFullSlotHeads(ctx, conn, heads, revisions, history)
	if err != nil {
		return err
	}
	if err := validateFullHistoryHeads(history, slots); err != nil {
		return err
	}
	if err := validateFullTuples(ctx, conn, heads); err != nil {
		return err
	}
	if err := validateFullAttributes(ctx, conn, heads); err != nil {
		return err
	}
	if err := validateFullEvents(ctx, conn, heads, revisions, slots, key); err != nil {
		return err
	}
	return validateFullIdempotency(ctx, conn, heads)
}

func runSQLiteIntegrityCheck(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var result string
		if err := rows.Scan(&result); err != nil || result != "ok" {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	if count != 1 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func runSQLiteForeignKeyCheck(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

func readCursorKey(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) ([32]byte, error) {
	var key [32]byte
	if queryer == nil {
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	var count int
	if err := queryer.QueryRowContext(ctx, "SELECT COUNT(*) FROM cadrena_meta").Scan(&count); err != nil {
		return key, mapError(ctx, err)
	}
	if count != 1 {
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	var length int
	err := queryer.QueryRowContext(ctx, "SELECT length(value) FROM cadrena_meta WHERE key = ?", cursorKeyMetaKey).Scan(&length)
	if errors.Is(err, sql.ErrNoRows) {
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	if err != nil || length != len(key) {
		if err != nil {
			return key, mapError(ctx, err)
		}
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	var value []byte
	err = queryer.QueryRowContext(ctx, "SELECT value FROM cadrena_meta WHERE key = ?", cursorKeyMetaKey).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	if err != nil || len(value) != len(key) {
		if err != nil {
			return key, mapError(ctx, err)
		}
		return key, sqliteError(policyengine.ErrorIntegrity)
	}
	copy(key[:], value)
	if err := contextError(ctx); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func validateRuntimeNamespaceHeads(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, data_generation, event_sequence, expired_through, effective_time_ns FROM namespace_heads")
	if err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace string
		var dataGeneration, eventSequence, expiredThrough int64
		var effective sql.NullInt64
		if err := rows.Scan(&namespace, &dataGeneration, &eventSequence, &expiredThrough, &effective); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if err := validateNamespaceHeadValues(namespace, dataGeneration, eventSequence, expiredThrough, effective); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	return validateRuntimeEventHeadBounds(ctx, conn)
}

// validateRuntimeEventHeadBounds is intentionally a bounded relation check:
// namespace_heads remains the outer startup metadata scan, while the
// state_events primary key answers each namespace probe without decoding or
// scanning event payloads. FullIntegrityCheck still owns exhaustive event
// validation.
func validateRuntimeEventHeadBounds(ctx context.Context, conn *sql.Conn) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	var found int
	err := conn.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1
		FROM namespace_heads AS heads
		WHERE EXISTS (
			SELECT 1
			FROM state_events AS events
			WHERE events.namespace = heads.namespace
			  AND events.sequence > heads.event_sequence
			LIMIT 1
		)
		LIMIT 1
	)`).Scan(&found)
	if err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if found != 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func validateNamespaceHeadValues(namespace string, dataGeneration, eventSequence, expiredThrough int64, effective sql.NullInt64) error {
	if _, err := policyengine.NewGetDataGenerationRequest(namespace); err != nil || dataGeneration < 0 || eventSequence < 0 || expiredThrough < 0 || expiredThrough > eventSequence {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	if effective.Valid {
		candidate := time.Unix(0, effective.Int64).UTC()
		_, nanos, ok := sqliteTimestamp(candidate)
		if !ok || nanos != effective.Int64 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

type integrityRevisionKey struct {
	namespace  string
	revisionID string
}

type integritySlotKey struct {
	namespace string
	slot      string
}

type integrityHistoryKey struct {
	namespace  string
	slot       string
	generation uint64
}

type integritySlotRecord struct {
	activation policyengine.Activation
}

func validateFullNamespaceHeads(ctx context.Context, conn *sql.Conn) (map[string]namespaceHead, error) {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, data_generation, event_sequence, expired_through, effective_time_ns FROM namespace_heads")
	if err != nil {
		return nil, mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	heads := make(map[string]namespaceHead)
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var namespace string
		var dataGeneration, eventSequence, expiredThrough int64
		var effective sql.NullInt64
		if err := rows.Scan(&namespace, &dataGeneration, &eventSequence, &expiredThrough, &effective); err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if err := validateNamespaceHeadValues(namespace, dataGeneration, eventSequence, expiredThrough, effective); err != nil {
			return nil, err
		}
		if _, exists := heads[namespace]; exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		head := namespaceHead{dataGeneration: dataGeneration, eventSequence: eventSequence, expiredThrough: expiredThrough}
		if effective.Valid {
			head.effectiveTimeNS = effective.Int64
			head.effectiveTimeIsSet = true
		}
		heads[namespace] = head
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(ctx, err)
	}
	return heads, nil
}

func validateFullRevisions(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead) (map[integrityRevisionKey]struct{}, error) {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, revision_id, artifact, provenance, published_at_ns FROM revisions")
	if err != nil {
		return nil, mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	revisions := make(map[integrityRevisionKey]struct{})
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var namespace, revisionID string
		var artifact, provenance []byte
		var publishedAtNS int64
		if err := rows.Scan(&namespace, &revisionID, &artifact, &provenance, &publishedAtNS); err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := heads[namespace]; !exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, err := decodeRevisionRecord(namespace, revisionID, artifact, provenance, publishedAtNS); err != nil {
			return nil, err
		}
		key := integrityRevisionKey{namespace: namespace, revisionID: revisionID}
		if _, exists := revisions[key]; exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		revisions[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(ctx, err)
	}
	return revisions, nil
}

func validateFullActivationHistory(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead, revisions map[integrityRevisionKey]struct{}) (map[integrityHistoryKey]integritySlotRecord, error) {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, slot, generation, revision_id, activated_at_ns FROM activation_history")
	if err != nil {
		return nil, mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	history := make(map[integrityHistoryKey]integritySlotRecord)
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var namespace, slot, revisionID string
		var generation, activatedAtNS int64
		if err := rows.Scan(&namespace, &slot, &generation, &revisionID, &activatedAtNS); err != nil || generation <= 0 {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := heads[namespace]; !exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := revisions[integrityRevisionKey{namespace: namespace, revisionID: revisionID}]; !exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		activation, err := policyengine.NewActivation(namespace, slot, revisionID, uint64(generation), time.Unix(0, activatedAtNS).UTC())
		if err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		key := integrityHistoryKey{namespace: namespace, slot: slot, generation: uint64(generation)}
		if _, exists := history[key]; exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		history[key] = integritySlotRecord{activation: activation}
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(ctx, err)
	}
	return history, nil
}

func validateFullSlotHeads(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead, revisions map[integrityRevisionKey]struct{}, history map[integrityHistoryKey]integritySlotRecord) (map[integritySlotKey]integritySlotRecord, error) {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, slot, revision_id, generation, activated_at_ns FROM slot_heads")
	if err != nil {
		return nil, mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	slots := make(map[integritySlotKey]integritySlotRecord)
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var namespace, slot, revisionID string
		var generation, activatedAtNS int64
		if err := rows.Scan(&namespace, &slot, &revisionID, &generation, &activatedAtNS); err != nil || generation <= 0 {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := heads[namespace]; !exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := revisions[integrityRevisionKey{namespace: namespace, revisionID: revisionID}]; !exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		activation, err := policyengine.NewActivation(namespace, slot, revisionID, uint64(generation), time.Unix(0, activatedAtNS).UTC())
		if err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		key := integritySlotKey{namespace: namespace, slot: slot}
		if _, exists := slots[key]; exists {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		historyRecord, exists := history[integrityHistoryKey{namespace: namespace, slot: slot, generation: uint64(generation)}]
		if !exists || historyRecord.activation.RevisionID() != activation.RevisionID() || !historyRecord.activation.ActivatedAt().Equal(activation.ActivatedAt()) {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		slots[key] = integritySlotRecord{activation: activation}
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(ctx, err)
	}
	return slots, nil
}

func validateFullHistoryHeads(history map[integrityHistoryKey]integritySlotRecord, slots map[integritySlotKey]integritySlotRecord) error {
	retained := make(map[integritySlotKey][]uint64, len(slots))
	for key := range history {
		slotKey := integritySlotKey{namespace: key.namespace, slot: key.slot}
		head, exists := slots[slotKey]
		if !exists || key.generation > head.activation.Generation() {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		retained[slotKey] = append(retained[slotKey], key.generation)
	}
	for slotKey, head := range slots {
		generations := retained[slotKey]
		if len(generations) == 0 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		sort.Slice(generations, func(left, right int) bool { return generations[left] < generations[right] })
		if generations[len(generations)-1] != head.activation.Generation() {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		for index := 1; index < len(generations); index++ {
			if generations[index] != generations[index-1]+1 {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		}
	}
	return nil
}

func validateFullTuples(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, tuple_key, subject_type, subject_id, subject_relation, relation, resource_type, resource_id, expires_at_ns FROM tuples")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace, subjectType, subjectID, subjectRelation, relation, resourceType, resourceID string
		var key []byte
		var expiresAt sql.NullInt64
		if err := rows.Scan(&namespace, &key, &subjectType, &subjectID, &subjectRelation, &relation, &resourceType, &resourceID, &expiresAt); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := heads[namespace]; !exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, err := decodeDurableTuple(key, subjectType, subjectID, subjectRelation, relation, resourceType, resourceID, expiresAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

type integrityAttributeKey struct {
	namespace string
	key       string
}

type integrityAttributeAncestorKey struct {
	namespace string
	key       string
	ancestor  string
}

func validateFullAttributes(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, attribute_key, entity_type, entity_id, path, value, expires_at_ns FROM attributes")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	expected := make(map[integrityAttributeAncestorKey]struct{})
	attributes := make(map[integrityAttributeKey]struct{})
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace, entityType, entityID string
		var key, path, value []byte
		var expiresAt sql.NullInt64
		if err := rows.Scan(&namespace, &key, &entityType, &entityID, &path, &value, &expiresAt); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := heads[namespace]; !exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		attribute, err := decodeDurableAttribute(key, path, value, entityType, entityID)
		if err != nil {
			return err
		}
		if expiresAt.Valid {
			candidate := time.Unix(0, expiresAt.Int64).UTC()
			_, nanos, ok := sqliteTimestamp(candidate)
			if !ok || nanos != expiresAt.Int64 {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		}
		attributeKey, err := attributeKeyFromAttribute(attribute)
		if err != nil {
			return err
		}
		attributeIdentity := integrityAttributeKey{namespace: namespace, key: string(key)}
		if _, exists := attributes[attributeIdentity]; exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		attributes[attributeIdentity] = struct{}{}
		prefixes, err := strictAttributePrefixes(attributeKey)
		if err != nil {
			return err
		}
		for _, prefix := range prefixes {
			expected[integrityAttributeAncestorKey{namespace: namespace, key: string(key), ancestor: string(prefix)}] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}

	ancestorRows, err := conn.QueryContext(ctx, "SELECT namespace, attribute_key, ancestor_path FROM attribute_ancestors")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = ancestorRows.Close() }()
	for ancestorRows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace string
		var key, ancestor []byte
		if err := ancestorRows.Scan(&namespace, &key, &ancestor); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, exists := attributes[integrityAttributeKey{namespace: namespace, key: string(key)}]; !exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, err := decodeAttributeKey(key); err != nil {
			return err
		}
		if _, err := decodeAttributeKey(ancestor); err != nil {
			return err
		}
		identity := integrityAttributeAncestorKey{namespace: namespace, key: string(key), ancestor: string(ancestor)}
		if _, exists := expected[identity]; !exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		delete(expected, identity)
	}
	if err := ancestorRows.Err(); err != nil {
		return mapError(ctx, err)
	}
	if len(expected) != 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

type integrityEventState struct {
	seen bool
	last int64
}

func validateFullEvents(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead, revisions map[integrityRevisionKey]struct{}, slots map[integritySlotKey]integritySlotRecord, key [32]byte) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, sequence, kind, payload, created_at_ns FROM state_events ORDER BY namespace, sequence")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	checker := &Store{cursorKey: key}
	states := make(map[string]integrityEventState)
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace, kind string
		var sequence, createdAtNS int64
		var payload []byte
		if err := rows.Scan(&namespace, &sequence, &kind, &payload, &createdAtNS); err != nil || sequence <= 0 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		head, exists := heads[namespace]
		if !exists || sequence > head.eventSequence || sequence <= head.expiredThrough {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		state := states[namespace]
		if !state.seen {
			if sequence != head.expiredThrough+1 {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		} else if sequence != state.last+1 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		event, err := decodeStateEvent(payload)
		if err != nil {
			return err
		}
		when := time.Unix(0, createdAtNS).UTC()
		_, nanos, valid := sqliteTimestamp(when)
		if !valid || nanos != createdAtNS || event.Namespace() != namespace || stateEventKindName(event.Kind()) != kind || !event.OccurredAt().Equal(when) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		cursor, err := checker.decodeCursor(event.Cursor(), cursorDomainEvent, namespace, "")
		if err != nil || cursor.position != uint64(sequence) || cursor.boundary > uint64(head.expiredThrough) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		switch event.Kind() {
		case policyengine.StateEventRevisionPublished:
			if _, exists := revisions[integrityRevisionKey{namespace: namespace, revisionID: event.RevisionID()}]; !exists {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		case policyengine.StateEventSlotActivated:
			slot, exists := slots[integritySlotKey{namespace: namespace, slot: event.Slot()}]
			if !exists || event.SlotGeneration() > slot.activation.Generation() {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			if _, exists := revisions[integrityRevisionKey{namespace: namespace, revisionID: event.RevisionID()}]; !exists {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		case policyengine.StateEventDataWritten:
			if event.DataGeneration() > uint64(head.dataGeneration) {
				return sqliteError(policyengine.ErrorIntegrity)
			}
		default:
			return sqliteError(policyengine.ErrorIntegrity)
		}
		states[namespace] = integrityEventState{seen: true, last: sequence}
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	for namespace, head := range heads {
		state := states[namespace]
		if (!state.seen && head.eventSequence != head.expiredThrough) || (state.seen && state.last != head.eventSequence) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

func validateFullIdempotency(ctx context.Context, conn *sql.Conn, heads map[string]namespaceHead) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, idempotency_key, fingerprint, response FROM idempotency_records")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	generationResponses := make(map[string]map[uint64]struct{}, len(heads))
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace, idempotencyKey string
		var fingerprint, response []byte
		if err := rows.Scan(&namespace, &idempotencyKey, &fingerprint, &response); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		head, exists := heads[namespace]
		if !exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, err := store.NewIdempotencyScope(namespace, store.IdempotencyWriteData, idempotencyKey); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if _, err := decodeIdempotencyFingerprint(fingerprint); err != nil {
			return err
		}
		decoded, err := decodeIdempotencyResponse(response, false)
		if err != nil || decoded.Generation() > uint64(head.dataGeneration) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		responses := generationResponses[namespace]
		if responses == nil {
			responses = make(map[uint64]struct{})
			generationResponses[namespace] = responses
		}
		if _, exists := responses[decoded.Generation()]; exists {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		responses[decoded.Generation()] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	for namespace, head := range heads {
		if uint64(len(generationResponses[namespace])) != uint64(head.dataGeneration) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

func validateFullValueBounds(ctx context.Context, conn *sql.Conn) error {
	checks := []struct {
		query string
		args  []any
	}{
		{query: "SELECT 1 FROM revisions WHERE length(CAST(namespace AS BLOB)) > ? OR length(CAST(revision_id AS BLOB)) > ? OR length(artifact) > ? OR length(provenance) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, policyengine.MaxIdentifierBytes, policyengine.MaxPolicyArtifactBytes, maxRevisionProvenanceBytes()}},
		{query: "SELECT 1 FROM slot_heads WHERE length(CAST(namespace AS BLOB)) > ? OR length(CAST(slot AS BLOB)) > ? OR length(CAST(revision_id AS BLOB)) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes}},
		{query: "SELECT 1 FROM activation_history WHERE length(CAST(namespace AS BLOB)) > ? OR length(CAST(slot AS BLOB)) > ? OR length(CAST(revision_id AS BLOB)) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes}},
		{query: "SELECT 1 FROM tuples WHERE length(CAST(namespace AS BLOB)) > ? OR length(tuple_key) > ? OR length(CAST(subject_type AS BLOB)) > ? OR length(CAST(subject_id AS BLOB)) > ? OR length(CAST(subject_relation AS BLOB)) > ? OR length(CAST(relation AS BLOB)) > ? OR length(CAST(resource_type AS BLOB)) > ? OR length(CAST(resource_id AS BLOB)) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, maxTupleKeyBytes(), policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes}},
		{query: "SELECT 1 FROM attributes WHERE length(CAST(namespace AS BLOB)) > ? OR length(attribute_key) > ? OR length(CAST(entity_type AS BLOB)) > ? OR length(CAST(entity_id AS BLOB)) > ? OR length(path) > ? OR length(value) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, maxAttributeKeyBytes(), policyengine.MaxIdentifierBytes, policyengine.MaxIdentifierBytes, policyengine.MaxAggregateInputBytes, maxAttributeValueBytes()}},
		{query: "SELECT 1 FROM attribute_ancestors WHERE length(CAST(namespace AS BLOB)) > ? OR length(attribute_key) > ? OR length(ancestor_path) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, maxAttributeKeyBytes(), policyengine.MaxAggregateInputBytes}},
		{query: "SELECT 1 FROM state_events WHERE length(CAST(namespace AS BLOB)) > ? OR length(CAST(kind AS BLOB)) > ? OR length(payload) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, 32, maxStateEventPayloadBytes()}},
		{query: "SELECT 1 FROM idempotency_records WHERE length(CAST(namespace AS BLOB)) > ? OR length(CAST(idempotency_key AS BLOB)) > ? OR length(fingerprint) > ? OR length(response) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes, policyengine.MaxIdentifierBytes, 1 + 32, 1 + 1 + 8}},
		{query: "SELECT 1 FROM namespace_heads WHERE length(CAST(namespace AS BLOB)) > ? LIMIT 1", args: []any{policyengine.MaxNamespaceBytes}},
	}
	for _, check := range checks {
		if err := contextError(ctx); err != nil {
			return err
		}
		var found int
		err := conn.QueryRowContext(ctx, check.query, check.args...).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return mapError(ctx, err)
		}
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func maxRevisionProvenanceBytes() int {
	return 1 + 1 + 2 + policyengine.MaxSourceNameBytes + 4 + policyengine.MaxPolicySourceBytes
}

func maxTupleKeyBytes() int {
	return 1 + 6*(2+policyengine.MaxIdentifierBytes)
}

func maxAttributeKeyBytes() int {
	return 1 + 2 + policyengine.MaxIdentifierBytes + 2 + policyengine.MaxIdentifierBytes + 4 + policyengine.MaxAggregateInputBytes
}

func maxAttributeValueBytes() int {
	return 1 + 1 + 4 + policyengine.MaxStringValueBytes
}

func maxStateEventPayloadBytes() int {
	return 1 + 1 + 2 + policyengine.MaxNamespaceBytes + 3*(2+policyengine.MaxIdentifierBytes) + 8 + 8 + 8 + 4
}

func integrityResultError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	category := categoryOfIntegrityError(err)
	switch category {
	case policyengine.ErrorCanceled, policyengine.ErrorDeadlineExceeded, policyengine.ErrorUnavailable,
		policyengine.ErrorFailedPrecondition, policyengine.ErrorInvalidArgument, policyengine.ErrorPermissionDenied,
		policyengine.ErrorResourceExhausted, policyengine.ErrorIntegrity:
		return sqliteError(category)
	default:
		return sqliteError(policyengine.ErrorIntegrity)
	}
}

func categoryOfIntegrityError(err error) policyengine.ErrorCategory {
	var engineErr *policyengine.EngineError
	if errors.As(err, &engineErr) {
		return engineErr.Category()
	}
	return ""
}
