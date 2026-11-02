-- Migration 0005: support candidate and discovered classifications, and probe source type
-- Rebuilds endpoints and endpoint_sources tables to expand CHECK constraints
-- while preserving all data, indexes, foreign keys and triggers.

PRAGMA foreign_keys = OFF;

-- 1. Rebuild endpoints table with expanded CHECK constraint for classification:
--    'shadow', 'documented', 'zombie', 'unknown', 'candidate', 'discovered'
CREATE TABLE endpoints_new (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id          TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    host               TEXT NOT NULL,
    method             TEXT NOT NULL CHECK (method IN ('GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE','TRACE')),
    path_template      TEXT NOT NULL,
    query_template     TEXT NOT NULL DEFAULT '',
    classification     TEXT NOT NULL CHECK (classification IN ('shadow','documented','zombie','unknown','candidate','discovered')),
    validation_status  TEXT NOT NULL CHECK (validation_status IN ('unvalidated','live','redirected','auth_required','not_found','error','blocked','skipped_budget')),
    response_status    INTEGER,
    fingerprint        TEXT NOT NULL,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL,
    first_seen_scan    TEXT REFERENCES scans(id),
    last_seen_scan     TEXT REFERENCES scans(id),
    origin             TEXT NOT NULL
);

INSERT INTO endpoints_new (
    id, org_id, target_id, host, method, path_template, query_template,
    classification, validation_status, response_status, fingerprint,
    first_seen_at, last_seen_at, first_seen_scan, last_seen_scan, origin
)
SELECT
    id, org_id, target_id, host, method, path_template, query_template,
    classification, validation_status, response_status, fingerprint,
    first_seen_at, last_seen_at, first_seen_scan, last_seen_scan, origin
FROM endpoints;

DROP TABLE endpoints;
ALTER TABLE endpoints_new RENAME TO endpoints;

CREATE UNIQUE INDEX ux_endpoints_identity ON endpoints(org_id, target_id, method, host, path_template, query_template);
CREATE INDEX ix_endpoints_target ON endpoints(target_id);
CREATE INDEX ix_endpoints_class ON endpoints(target_id, classification);


-- 2. Rebuild endpoint_sources table with expanded CHECK constraint for source_type:
--    adds 'probe'
CREATE TABLE endpoint_sources_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id  TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_type  TEXT NOT NULL CHECK (source_type IN ('html','javascript','source_map','openapi','swagger_ui','redoc','postman','docs','robots','sitemap','har','crawler','graphql','manual','probe')),
    source_url   TEXT NOT NULL,
    location     TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT 'GET',
    snippet      TEXT NOT NULL DEFAULT '',
    extractor    TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

INSERT INTO endpoint_sources_new (
    id, endpoint_id, scan_id, source_type, source_url, location, method, snippet, extractor, created_at
)
SELECT
    id, endpoint_id, scan_id, source_type, source_url, location, method, snippet, extractor, created_at
FROM endpoint_sources;

DROP TABLE endpoint_sources;
ALTER TABLE endpoint_sources_new RENAME TO endpoint_sources;

CREATE INDEX ix_endpoint_sources_ep ON endpoint_sources(endpoint_id);
CREATE INDEX ix_endpoint_sources_scan ON endpoint_sources(scan_id);

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
