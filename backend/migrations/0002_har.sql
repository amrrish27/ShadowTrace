-- HAR imports are stored already redacted (redaction happens at import time).
CREATE TABLE har_imports (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id   TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    entries     TEXT NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  INTEGER NOT NULL
);
CREATE INDEX ix_har_target ON har_imports(target_id);
