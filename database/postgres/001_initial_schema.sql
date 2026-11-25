-- Kryvnix Antivirus Central Database Schema (PostgreSQL 16)
-- Phase 01 Migration: 001_initial_schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'Analyst' CHECK (role IN ('Admin', 'Analyst', 'Viewer', 'Standard')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(128) NOT NULL,
    agent_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    db_version VARCHAR(32) NOT NULL DEFAULT 'v2025.01.15',
    realtime_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(32) NOT NULL DEFAULT 'Protected',
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS update_packages (
    version VARCHAR(32) PRIMARY KEY,
    signature_count INTEGER NOT NULL DEFAULT 0,
    yara_count INTEGER NOT NULL DEFAULT 0,
    sha256_digest CHAR(64) NOT NULL,
    ed25519_signature TEXT NOT NULL,
    changelog TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS malware_signatures (
    id BIGSERIAL PRIMARY KEY,
    sha256 CHAR(64) NOT NULL UNIQUE,
    threat_name VARCHAR(255) NOT NULL,
    category VARCHAR(32) NOT NULL CHECK (category IN ('Trojan', 'Ransomware', 'Spyware', 'Worm', 'Backdoor', 'Adware', 'Other')),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    package_version VARCHAR(32) REFERENCES update_packages(version) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id BIGSERIAL PRIMARY KEY,
    rule_name VARCHAR(128) NOT NULL UNIQUE,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    rule_source TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_mode VARCHAR(32) NOT NULL CHECK (scan_mode IN ('Quick', 'Full', 'Custom', 'Realtime')),
    target_path TEXT NOT NULL DEFAULT '',
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'Completed',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_session_id UUID REFERENCES scan_sessions(id) ON DELETE SET NULL,
    file_path TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    threat_name VARCHAR(255) NOT NULL,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    detection_method VARCHAR(32) NOT NULL,
    heuristic_score INTEGER NOT NULL DEFAULT 0,
    action_taken VARCHAR(32) NOT NULL DEFAULT 'Detected',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS quarantine_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    original_name VARCHAR(255) NOT NULL,
    original_path TEXT NOT NULL,
    vault_file_name VARCHAR(255) NOT NULL,
    threat_name VARCHAR(255) NOT NULL,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    file_size BIGINT NOT NULL DEFAULT 0,
    encryption_alg VARCHAR(32) NOT NULL DEFAULT 'AES-256-GCM',
    status VARCHAR(32) NOT NULL DEFAULT 'Quarantined',
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signatures_category ON malware_signatures(category);
CREATE INDEX IF NOT EXISTS idx_detections_device_time ON detections(device_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_device_time ON scan_sessions(device_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_device_status ON quarantine_records(device_id, status);
