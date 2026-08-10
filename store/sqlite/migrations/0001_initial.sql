CREATE TABLE cadrena_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE namespace_heads (
    namespace TEXT PRIMARY KEY,
    data_generation INTEGER NOT NULL DEFAULT 0 CHECK (data_generation >= 0),
    event_sequence INTEGER NOT NULL DEFAULT 0 CHECK (event_sequence >= 0),
    expired_through INTEGER NOT NULL DEFAULT 0 CHECK (expired_through >= 0),
    effective_time_ns INTEGER
);

CREATE TABLE revisions (
    namespace TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    artifact BLOB NOT NULL,
    provenance BLOB NOT NULL,
    published_at_ns INTEGER NOT NULL,
    PRIMARY KEY (namespace, revision_id)
);

CREATE TABLE slot_heads (
    namespace TEXT NOT NULL,
    slot TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    activated_at_ns INTEGER NOT NULL,
    PRIMARY KEY (namespace, slot),
    FOREIGN KEY (namespace, revision_id) REFERENCES revisions(namespace, revision_id)
);

CREATE TABLE activation_history (
    namespace TEXT NOT NULL,
    slot TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    revision_id TEXT NOT NULL,
    activated_at_ns INTEGER NOT NULL,
    PRIMARY KEY (namespace, slot, generation),
    FOREIGN KEY (namespace, revision_id) REFERENCES revisions(namespace, revision_id)
);

CREATE TABLE tuples (
    namespace TEXT NOT NULL,
    tuple_key BLOB NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_relation TEXT NOT NULL,
    relation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    expires_at_ns INTEGER,
    PRIMARY KEY (namespace, tuple_key)
);

CREATE TABLE attributes (
    namespace TEXT NOT NULL,
    attribute_key BLOB NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    path BLOB NOT NULL,
    value BLOB NOT NULL,
    expires_at_ns INTEGER,
    PRIMARY KEY (namespace, attribute_key)
);

CREATE TABLE attribute_ancestors (
    namespace TEXT NOT NULL,
    attribute_key BLOB NOT NULL,
    ancestor_path BLOB NOT NULL,
    PRIMARY KEY (namespace, attribute_key, ancestor_path),
    FOREIGN KEY (namespace, attribute_key) REFERENCES attributes(namespace, attribute_key) ON DELETE CASCADE
);

CREATE TABLE state_events (
    namespace TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at_ns INTEGER NOT NULL,
    PRIMARY KEY (namespace, sequence)
);

CREATE TABLE idempotency_records (
    namespace TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    fingerprint BLOB NOT NULL,
    response BLOB NOT NULL,
    PRIMARY KEY (namespace, idempotency_key)
);

CREATE INDEX idx_revisions_namespace_published_at
    ON revisions(namespace, published_at_ns DESC, revision_id);

CREATE INDEX idx_activation_history_namespace_slot_generation
    ON activation_history(namespace, slot, generation DESC);

CREATE INDEX idx_tuples_namespace_resource_relation_subject
    ON tuples(namespace, resource_type, resource_id, relation, subject_type, subject_id, subject_relation);

CREATE INDEX idx_tuples_namespace_subject_relation_resource
    ON tuples(namespace, subject_type, subject_id, subject_relation, relation, resource_type, resource_id);

CREATE INDEX idx_attributes_namespace_entity_path
    ON attributes(namespace, entity_type, entity_id, path);

CREATE INDEX idx_attribute_ancestors_namespace_ancestor_path
    ON attribute_ancestors(namespace, ancestor_path, attribute_key);

CREATE INDEX idx_state_events_namespace_sequence
    ON state_events(namespace, sequence);
