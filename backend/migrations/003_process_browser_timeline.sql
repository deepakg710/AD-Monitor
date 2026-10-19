-- Migration 002: Read-Only Process Monitor, Browser Activity (MV3 + Native Host), and Investigation Timeline
-- Preserves all existing tables and data. Marks pre-existing unverified host-polled records for provenance review.

CREATE TABLE IF NOT EXISTS process_snapshots(
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    collector_id TEXT NOT NULL REFERENCES collectors(id),
    boot_session_id TEXT,
    sampled_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    collector_version TEXT,
    logical_cpus INTEGER,
    total_cpu_percent REAL,
    memory_used_bytes INTEGER,
    memory_total_bytes INTEGER,
    process_count INTEGER NOT NULL DEFAULT 0,
    is_complete INTEGER NOT NULL DEFAULT 1,
    batch_index INTEGER NOT NULL DEFAULT 1,
    batch_total INTEGER NOT NULL DEFAULT 1,
    sample_duration_ms INTEGER,
    errors TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_proc_snap_device_time ON process_snapshots(device_id, sampled_at DESC);

CREATE TABLE IF NOT EXISTS process_instances(
    instance_key TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    boot_session_id TEXT,
    pid INTEGER NOT NULL,
    process_guid TEXT,
    name TEXT NOT NULL,
    executable_path TEXT,
    canonical_path TEXT,
    command_line TEXT,
    command_line_state TEXT NOT NULL DEFAULT 'Not collected',
    user_sid TEXT,
    account TEXT,
    session_id INTEGER,
    creation_time TEXT,
    parent_instance_key TEXT,
    parent_pid INTEGER,
    parent_name TEXT,
    parent_confidence TEXT NOT NULL DEFAULT 'Unavailable',
    identity_confidence TEXT NOT NULL DEFAULT 'Snapshot PID+CreationTime',
    signature_state TEXT NOT NULL DEFAULT 'Not collected',
    signer TEXT,
    sha256 TEXT,
    hash_state TEXT NOT NULL DEFAULT 'Not collected',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    exited_at TEXT,
    no_longer_observed_after TEXT,
    observed_state TEXT NOT NULL DEFAULT 'Observed',
    source_kind TEXT NOT NULL DEFAULT 'Snapshot',
    source_event_ids TEXT NOT NULL DEFAULT '[]',
    raw_metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_proc_inst_device_state ON process_instances(device_id, observed_state, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_proc_inst_user ON process_instances(user_sid, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_proc_inst_pid ON process_instances(device_id, pid, creation_time);
CREATE INDEX IF NOT EXISTS ix_proc_inst_parent ON process_instances(parent_instance_key);

CREATE TABLE IF NOT EXISTS process_samples(
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES process_snapshots(id) ON DELETE CASCADE,
    instance_key TEXT NOT NULL REFERENCES process_instances(instance_key) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id),
    sampled_at TEXT NOT NULL,
    cpu_percent REAL,
    cpu_time_ms INTEGER,
    working_set_bytes INTEGER,
    private_bytes INTEGER,
    handle_count INTEGER,
    thread_count INTEGER,
    state_label TEXT NOT NULL DEFAULT 'Observed'
);
CREATE INDEX IF NOT EXISTS ix_proc_samples_inst ON process_samples(instance_key, sampled_at DESC);
CREATE INDEX IF NOT EXISTS ix_proc_samples_snap ON process_samples(snapshot_id);
CREATE INDEX IF NOT EXISTS ix_proc_samples_device_time ON process_samples(device_id, sampled_at DESC);

CREATE TABLE IF NOT EXISTS process_lifecycle_events(
    id TEXT PRIMARY KEY,
    event_id TEXT REFERENCES events(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    instance_key TEXT REFERENCES process_instances(instance_key),
    event_type TEXT NOT NULL CHECK(event_type IN ('Started','Exited')),
    event_time TEXT NOT NULL,
    received_at TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_guid TEXT,
    name TEXT NOT NULL,
    executable_path TEXT,
    canonical_path TEXT,
    command_line TEXT,
    command_line_state TEXT NOT NULL DEFAULT 'Not collected',
    user_sid TEXT,
    account TEXT,
    parent_pid INTEGER,
    parent_process_guid TEXT,
    parent_image TEXT,
    exit_code TEXT,
    source_channel TEXT NOT NULL,
    identity_key TEXT UNIQUE NOT NULL,
    raw_metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_proc_life_device_time ON process_lifecycle_events(device_id, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_proc_life_inst ON process_lifecycle_events(instance_key, event_time DESC);

CREATE TABLE IF NOT EXISTS browser_profiles(
    profile_id TEXT PRIMARY KEY,
    collector_id TEXT NOT NULL REFERENCES collectors(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_sid TEXT NOT NULL,
    account TEXT NOT NULL,
    browser_name TEXT NOT NULL,
    browser_version TEXT,
    extension_id TEXT NOT NULL,
    extension_version TEXT,
    profile_label TEXT,
    enrollment_state TEXT NOT NULL DEFAULT 'Enrolled',
    paused_at TEXT,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT,
    last_delivery_at TEXT,
    native_host_version TEXT,
    dropped_count INTEGER NOT NULL DEFAULT 0,
    queue_depth INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    diagnostics TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_browser_prof_device_user ON browser_profiles(device_id, user_sid);

CREATE TABLE IF NOT EXISTS browser_collection_gaps(
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES browser_profiles(profile_id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_sid TEXT NOT NULL,
    gap_kind TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_browser_gaps_prof ON browser_collection_gaps(profile_id, started_at DESC);

CREATE TABLE IF NOT EXISTS browser_navigations(
    id TEXT PRIMARY KEY,
    identity_key TEXT UNIQUE NOT NULL,
    profile_id TEXT NOT NULL REFERENCES browser_profiles(profile_id),
    collector_id TEXT NOT NULL REFERENCES collectors(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_sid TEXT NOT NULL,
    account TEXT NOT NULL,
    browser_name TEXT NOT NULL,
    navigation_time TEXT NOT NULL,
    received_at TEXT NOT NULL,
    normalized_domain TEXT NOT NULL,
    scheme TEXT NOT NULL CHECK(scheme IN ('http','https')),
    port INTEGER,
    transition_type TEXT,
    transition_qualifiers TEXT NOT NULL DEFAULT '[]',
    visit_kind TEXT NOT NULL DEFAULT 'Top-level navigation',
    tab_id INTEGER,
    frame_id INTEGER NOT NULL DEFAULT 0,
    sanitization_verified INTEGER NOT NULL DEFAULT 1,
    raw_sanitized_evidence TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_nav_device_time ON browser_navigations(device_id, navigation_time DESC);
CREATE INDEX IF NOT EXISTS ix_nav_user_time ON browser_navigations(user_sid, navigation_time DESC);
CREATE INDEX IF NOT EXISTS ix_nav_domain ON browser_navigations(normalized_domain, navigation_time DESC);

CREATE TABLE IF NOT EXISTS browser_downloads(
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES browser_profiles(profile_id),
    collector_id TEXT NOT NULL REFERENCES collectors(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_sid TEXT NOT NULL,
    account TEXT NOT NULL,
    browser_name TEXT NOT NULL,
    browser_download_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    updated_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    filename TEXT,
    final_path TEXT,
    canonical_path TEXT,
    source_domain TEXT,
    final_domain TEXT,
    referrer_domain TEXT,
    mime_type TEXT,
    file_extension TEXT,
    bytes_received INTEGER,
    total_bytes INTEGER,
    final_size_bytes INTEGER,
    state TEXT NOT NULL CHECK(state IN ('in_progress','completed','interrupted','canceled','unknown')),
    interrupt_reason TEXT,
    danger_type TEXT,
    exists_on_disk INTEGER,
    sha256 TEXT,
    hash_state TEXT NOT NULL DEFAULT 'Not collected',
    raw_sanitized_evidence TEXT NOT NULL DEFAULT '{}',
    UNIQUE(profile_id, browser_download_id)
);
CREATE INDEX IF NOT EXISTS ix_dl_device_time ON browser_downloads(device_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_dl_user_time ON browser_downloads(user_sid, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_dl_path ON browser_downloads(device_id, canonical_path);

CREATE TABLE IF NOT EXISTS browser_download_revisions(
    id TEXT PRIMARY KEY,
    download_id TEXT NOT NULL REFERENCES browser_downloads(id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    state TEXT NOT NULL,
    filename TEXT,
    final_path TEXT,
    bytes_received INTEGER,
    total_bytes INTEGER,
    danger_type TEXT,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_dl_rev_download ON browser_download_revisions(download_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS correlation_links(
    id TEXT PRIMARY KEY,
    case_key TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id),
    user_sid TEXT,
    account TEXT,
    link_kind TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    event_time TEXT NOT NULL,
    time_delta_seconds REAL,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL DEFAULT 1,
    confidence TEXT NOT NULL,
    relationship_label TEXT NOT NULL,
    matched_fields TEXT NOT NULL DEFAULT '[]',
    missing_fields TEXT NOT NULL DEFAULT '[]',
    competing_candidates TEXT NOT NULL DEFAULT '[]',
    what_is_established TEXT NOT NULL,
    what_is_not_established TEXT NOT NULL,
    justification TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'Needs review',
    reviewed_by TEXT,
    reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_corr_case ON correlation_links(case_key, event_time);
CREATE INDEX IF NOT EXISTS ix_corr_device_time ON correlation_links(device_id, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_corr_user_time ON correlation_links(user_sid, event_time DESC);
CREATE INDEX IF NOT EXISTS ix_corr_source ON correlation_links(source_type, source_id);
CREATE INDEX IF NOT EXISTS ix_corr_target ON correlation_links(target_type, target_id);

CREATE TABLE IF NOT EXISTS correlation_reviews(
    id TEXT PRIMARY KEY,
    case_key TEXT NOT NULL,
    link_id TEXT REFERENCES correlation_links(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decision TEXT NOT NULL,
    note TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_corr_rev_case ON correlation_reviews(case_key, created_at DESC);

-- Mark pre-migration records that relied on default actor fallback or host-side USB polling for provenance review
UPDATE events
SET attribution = attribution || ' [Provenance review: pre-migration unverified actor fallback]'
WHERE provider IN ('ADMonitor.InstrumentedOperation', 'ADMonitor.MetadataSnapshot')
  AND user_sid IS NULL
  AND account = 'LAB\sales.demo'
  AND instr(attribution, 'Provenance review') = 0;

UPDATE usb
SET evidence_type = 'device_presence_only [Provenance review: verify host vs endpoint origin]'
WHERE account = 'LAB\sales.demo'
  AND instr(evidence_type, 'Provenance review') = 0;
