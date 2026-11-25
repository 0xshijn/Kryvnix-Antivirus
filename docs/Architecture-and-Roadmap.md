# Kryvnix Antivirus — Architecture & 10-Phase Implementation Plan

## 1. System Overview

**Kryvnix Antivirus** is a commercial-grade Windows endpoint security platform built with a hybrid architecture:

- **Desktop Client (C# / .NET 10 / WPF / MVVM)**: Modern Fluent Dark UI with custom Windows 11 chrome, system tray integration, LiveCharts2 analytics, local SQLite persistence, Named Pipe IPC client, and hybrid local scanning/quarantine fallback.
- **Native Protection Engine & Windows Service (C++20 / CMake / vcpkg)**: High-throughput multithreaded file scanner, SHA-256 signature lookup, libyara rule engine, PE parser & heuristic analyzer, AES-256-GCM encrypted quarantine vault, and real-time file system monitor exposed over Windows Named Pipe (`\\.\pipe\KryvnixAntivirusPipe`).
- **Central Management Backend & Admin Dashboard (PostgreSQL + REST API + React)**: RBAC authentication, endpoint inventory, malware signature & YARA rule CRUD, Ed25519-signed signature package builder, device heartbeat, and telemetry analytics.

## 2. Entity-Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOGS : records
    DEVICES ||--o{ SCAN_SESSIONS : runs
    DEVICES ||--o{ DETECTIONS : reports
    DEVICES ||--o{ QUARANTINE_RECORDS : isolates
    SCAN_SESSIONS ||--o{ DETECTIONS : discovers
    MALWARE_SIGNATURES ||--o{ DETECTIONS : matches
    YARA_RULES ||--o{ DETECTIONS : triggers
    UPDATE_PACKAGES ||--o{ MALWARE_SIGNATURES : bundles

    USERS {
        uuid id PK
        varchar username UK
        varchar email UK
        varchar password_hash
        varchar role
        boolean is_active
        timestamp created_at
    }

    DEVICES {
        uuid id PK
        varchar hostname
        varchar os_version
        varchar agent_version
        varchar db_version
        varchar status
        timestamp last_heartbeat_at
    }

    MALWARE_SIGNATURES {
        bigint id PK
        char sha256 UK
        varchar threat_name
        varchar category
        varchar severity
        varchar package_version
        timestamp added_at
    }

    YARA_RULES {
        bigint id PK
        varchar rule_name UK
        varchar category
        varchar severity
        text rule_source
        boolean enabled
        timestamp updated_at
    }

    SCAN_SESSIONS {
        uuid id PK
        uuid device_id FK
        varchar scan_mode
        varchar target_path
        int files_scanned
        int threats_found
        bigint duration_ms
        varchar status
        timestamp started_at
        timestamp completed_at
    }

    DETECTIONS {
        uuid id PK
        uuid device_id FK
        uuid scan_session_id FK
        varchar file_path
        char sha256
        varchar threat_name
        varchar category
        varchar severity
        varchar detection_method
        int heuristic_score
        varchar action_taken
        timestamp detected_at
    }

    QUARANTINE_RECORDS {
        uuid id PK
        uuid device_id FK
        varchar original_name
        varchar original_path
        varchar vault_file_name
        varchar threat_name
        varchar category
        varchar severity
        char sha256
        bigint file_size
        varchar encryption_alg
        varchar status
        timestamp quarantined_at
    }

    UPDATE_PACKAGES {
        varchar version PK
        int signature_count
        int yara_count
        varchar sha256_digest
        text ed25519_signature
        text changelog
        timestamp published_at
    }
```

## 3. Windows Named Pipe IPC Protocol

- **Pipe Name**: `\\.\pipe\KryvnixAntivirusPipe`
- **Framing**: 4-byte little-endian `uint32` payload length prefix followed by UTF-8 JSON object.
- **Message Types**:
  - `ping` / `get_status` -> returns engine version, service health, real-time module states, active DB version.
  - `start_scan` (`Quick`, `Full`, `Custom`, `targets[]`) -> streams `scan_progress` frames and `detection_found` frames until `scan_completed`.
  - `pause_scan` / `resume_scan` / `cancel_scan` -> controls active scan job.
  - `quarantine_file` / `restore_file` / `delete_quarantine` -> executes privileged vault operations.
  - `set_realtime_config` -> toggles File Monitor, Process Monitor, Network Shield, Behavior Detection, and Exclusion list.
  - `apply_update` -> verifies Ed25519 signature and applies atomic SQLite signature package update.

## 4. 10-Phase Roadmap Checklist

- **Phase 01 · Project Setup (Tuần 1)**: Git repo, CMake & vcpkg manifest, PostgreSQL & SQLite migrations, ERD, Docker Compose.
- **Phase 02 · Core Scanner (Tuần 2–3)**: File Scanner, SHA-256 Engine, Signature Repository, Multithread Scan Queue, CLI, Unit Tests.
- **Phase 03 · Detection Engine (Tuần 4–5)**: libyara integration, PE Parser, Entropy Analyzer, Import Analyzer, Heuristic Scoring, Detection Repository.
- **Phase 04 · Quarantine & Service (Tuần 6)**: AES-256-GCM Encrypted Quarantine Storage, Restore & Delete, Windows Service, Named Pipe IPC, ACL tests.
- **Phase 05 · Backend API (Tuần 7)**: Auth & RBAC, Device Management, Signature CRUD, Scan & Detection API, Audit Logging.
- **Phase 06 · Desktop GUI (Tuần 8)**: C# .NET 10 WPF MVVM app — Dashboard, Quick/Full/Custom Scan, Scan Progress, Realtime Protection, Quarantine, History, Updates, Settings.
- **Phase 07 · Update & Sync (Tuần 9)**: Signature Package Builder, Ed25519 Verification, SQLite Update Transaction, Offline Sync Queue, Device Heartbeat.
- **Phase 08 · Realtime Protection (Tuần 10)**: File System Monitor, Event Queue, Realtime Scanner, Exclusion Filter, Security Policies.
- **Phase 09 · Admin Dashboard (Tuần 11)**: React Dashboard, Endpoint Management, Malware DB & YARA Management, Reports & Statistics.
- **Phase 10 · Testing & Release (Tuần 12)**: EICAR Test, False Positive Test, Performance Benchmark, Security Test, Windows Installer, Documentation.
