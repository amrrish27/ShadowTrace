-- Lab grants and worker liveness.
--
-- `lab_grant` is an HMAC (ST_SECRET_KEY) over target_id|scheme|host|port, issued by the
-- API only while the operator allow-list contains that exact pair. The scanner verifies
-- it instead of trusting a target record blindly; see app/security/labgrant.py.
ALTER TABLE targets ADD COLUMN lab_grant TEXT;
ALTER TABLE targets ADD COLUMN lab_grant_at INTEGER;

-- Worker liveness. One row per worker id, refreshed on every poll, so the API can say
-- whether scans will actually be processed ("worker: alive / last seen 2s ago").
CREATE TABLE worker_heartbeats (
    worker_id   TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL DEFAULT '',
    pid         INTEGER,
    started_at  INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    scans_run   INTEGER NOT NULL DEFAULT 0,
    version     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_worker_heartbeats_seen ON worker_heartbeats(last_seen_at);
