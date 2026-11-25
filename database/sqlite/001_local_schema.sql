-- Kryvnix Antivirus Local Endpoint Database Schema (SQLite 3)
-- Shared by Desktop WPF Application & Native C++ Engine

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    threat_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    package_version TEXT NOT NULL DEFAULT 'v2025.01.15',
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    scan_mode TEXT NOT NULL,
    target_path TEXT NOT NULL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    scan_session_id TEXT,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    detection_method TEXT NOT NULL,
    heuristic_score INTEGER NOT NULL DEFAULT 0,
    action_taken TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    original_path TEXT NOT NULL,
    vault_file_path TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    nonce_base64 TEXT NOT NULL DEFAULT '',
    tag_base64 TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Quarantined',
    quarantined_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Info',
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exclusions (
    id TEXT PRIMARY KEY,
    exclusion_type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_history (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    signatures_added INTEGER NOT NULL DEFAULT 0,
    total_signatures INTEGER NOT NULL DEFAULT 0,
    verified_ed25519 INTEGER NOT NULL DEFAULT 1,
    changelog TEXT NOT NULL DEFAULT '',
    installed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_local_detections_time ON detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_local_detections_cat ON detections(category);
CREATE INDEX IF NOT EXISTS idx_local_activity_time ON activity_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_local_scans_time ON scan_sessions(started_at DESC);
