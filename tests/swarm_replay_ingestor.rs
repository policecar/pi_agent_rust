#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pi::swarm_replay::{
    SWARM_REPLAY_POLICY_REPORT_SCHEMA, SWARM_REPLAY_REPORT_SCHEMA, SWARM_REPLAY_TRACE_SCHEMA,
    SwarmReplayBaselinePolicy, SwarmReplayEvent, SwarmReplayEventUncertainty, SwarmReplayGuards,
    SwarmReplayIngestRequest, SwarmReplayOrdering, SwarmReplayPolicyDecision,
    SwarmReplayRedactionSummary, SwarmReplayTrace, SwarmReplayUncertaintySummary,
    build_swarm_replay_trace, default_swarm_replay_baseline_policies,
    evaluate_swarm_replay_baseline_policies, replay_swarm_trace,
};
use serde_json::{Value, json};

const GENERATED_AT: &str = "2026-05-13T18:40:00Z";
const GOLDEN_TRACE: &str = "tests/golden_corpus/swarm_replay_trace/normalized_trace.json";

type TestResult = Result<(), Box<dyn Error>>;

static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_workspace(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let target_root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"),
        PathBuf::from,
    );
    let root = target_root
        .join("swarm_replay_ingestor_tests")
        .join(format!("{name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn write_text(root: &Path, rel: &str, text: &str) -> std::io::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)
}

fn write_json(root: &Path, rel: &str, value: &Value) -> std::io::Result<()> {
    write_text(root, rel, &serde_json::to_string_pretty(value)?)
}

fn load_json(rel: &str) -> Result<Value, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let raw = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn base_request(root: &Path) -> SwarmReplayIngestRequest {
    SwarmReplayIngestRequest::new("fixture-clean-replay-trace", GENERATED_AT, root)
        .with_git_identity("abc123", "main")
        .with_source_override("agent_mail_archive", "mail/archive.json")
        .with_source_override("git_refs", "git/refs.json")
        .with_source_override("validation_command_records", "validation/records.json")
        .with_source_override("swarm_flight_recorder", "flight/events.jsonl")
        .with_source_override("swarm_activity_ledger", "activity/events.jsonl")
}

fn write_clean_sources(root: &Path, include_agent_mail: bool) -> std::io::Result<()> {
    write_text(
        root,
        ".beads/issues.jsonl",
        r#"{"id":"bd-clean","status":"in_progress","priority":3,"assignee":"AmberOsprey","updated_at":"2026-05-13T18:00:00Z"}"#,
    )?;
    write_text(root, ".beads/beads.db", "sqlite fixture bytes")?;
    if include_agent_mail {
        write_json(
            root,
            "mail/archive.json",
            &json!({
                "messages": [{
                    "thread_id": "bd-clean",
                    "sender": "AmberOsprey",
                    "recipients": ["SilentReef"],
                    "importance": "normal",
                    "ack_required": true,
                    "created_at": "2026-05-13T18:01:00Z",
                    "body": "SECRET BODY SHOULD NOT SURVIVE"
                }],
                "reservations": [{
                    "id": "res-1",
                    "path_patterns": ["src/swarm_replay.rs"],
                    "exclusive": true,
                    "ttl_seconds": 3600,
                    "reason": "bd-in57w.2",
                    "holder": "AmberOsprey",
                    "created_at": "2026-05-13T18:02:00Z"
                }],
                "reservation_conflicts": [{
                    "path_pattern": "src/doctor.rs",
                    "holder": "SunnyBeacon",
                    "conflict_reason": "active exclusive lease",
                    "created_at": "2026-05-13T18:03:00Z"
                }],
                "build_slots": [{
                    "slot": "cargo-all-targets",
                    "holder": "AmberOsprey",
                    "state": "released",
                    "expires_at_utc": "2026-05-13T19:00:00Z",
                    "created_at": "2026-05-13T18:04:00Z"
                }]
            }),
        )?;
    }
    write_json(
        root,
        "docs/evidence/doctor-swarm.json",
        &json!({
            "findings": [{
                "finding_id": "mail_degraded",
                "severity": "degraded",
                "surface": "agent_mail",
                "status": "observed",
                "created_at": "2026-05-13T18:05:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/rch-queue-status.json",
        &json!({
            "jobs": [{
                "job_id": "rch-1",
                "state": "finished",
                "worker": "worker-redacted",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 0,
                "created_at": "2026-05-13T18:06:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/swarm-operator-runpack.json",
        &json!({
            "recommendations": [{
                "action": "continue_bd_in57w_2",
                "severity": "normal",
                "evidence_paths": ["docs/contracts/swarm-replay-trace-contract.json"],
                "operator_notes": "read-only replay ingestion",
                "created_at": "2026-05-13T18:07:00Z"
            }],
            "operator_handoff": {
                "handoff_id": "handoff-clean",
                "summary": "continue replay lab",
                "next_actions": ["implement replay engine"],
                "evidence_paths": ["tests/golden_corpus/swarm_replay_trace/normalized_trace.json"],
                "created_at": "2026-05-13T18:08:00Z"
            }
        }),
    )?;
    write_json(
        root,
        "git/refs.json",
        &json!({
            "head": "abc123",
            "branch": "main",
            "dirty": false,
            "changed_paths": [],
            "created_at": "2026-05-13T18:09:00Z"
        }),
    )?;
    write_json(
        root,
        "validation/records.json",
        &json!({
            "commands": [{
                "command": "rch exec -- cargo test --test swarm_replay_ingestor",
                "runner": "rch",
                "exit_code": 0,
                "target_dir": "/data/tmp/pi_agent_rust_cargo/amberosprey/target",
                "tmpdir": "/data/tmp/pi_agent_rust_cargo/amberosprey/tmp",
                "created_at": "2026-05-13T18:10:00Z"
            }],
            "artifacts": [{
                "artifact_path": "tests/golden_corpus/swarm_replay_trace/normalized_trace.json",
                "artifact_schema": "pi.swarm.replay_trace.v1",
                "verdict": "pass",
                "command": "cargo test --test swarm_replay_ingestor",
                "created_at": "2026-05-13T18:11:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/context-intelligence-closeout-gate.json",
        &json!({
            "schema": "pi.context_intelligence.closeout_gate.v1",
            "verdict": "pass",
            "generated_at": "2026-05-13T18:12:00Z"
        }),
    )?;
    write_text(
        root,
        "flight/events.jsonl",
        r#"{"schema":"pi.swarm.flight_recorder.event.v1","event_kind":"agent_turn","agent_name":"AmberOsprey","created_at":"2026-05-13T18:13:00Z"}"#,
    )?;
    write_text(
        root,
        "activity/events.jsonl",
        r#"{"schema":"pi.swarm.activity_ledger.v1","event_kind":"operator_handoff","handoff_id":"activity-handoff","summary":"handoff from activity ledger","next_actions":["inspect replay"],"evidence_paths":["tests/full_suite_gate/swarm_activity_digest.json"],"created_at":"2026-05-13T18:14:00Z"}"#,
    )
}

fn source_row<'a>(
    trace: &'a SwarmReplayTrace,
    source_id: &str,
) -> Result<&'a pi::swarm_replay::SwarmReplaySourceInventoryRow, String> {
    trace
        .source_inventory
        .iter()
        .find(|row| row.source_id == source_id)
        .ok_or_else(|| format!("missing source row {source_id}"))
}

fn event_types(trace: &SwarmReplayTrace) -> BTreeSet<String> {
    trace
        .events
        .iter()
        .map(|event| event.event_type.clone())
        .collect()
}

fn assert_monotonic_sequence(trace: &SwarmReplayTrace) -> TestResult {
    for (index, event) in trace.events.iter().enumerate() {
        let expected = u64::try_from(index + 1)?;
        assert_eq!(event.sequence, expected);
    }
    Ok(())
}

fn replay_event(
    event_id: &str,
    sequence: u64,
    occurred_at_utc: &str,
    event_type: &str,
    source_ref: &str,
    payload: Value,
) -> SwarmReplayEvent {
    SwarmReplayEvent {
        event_id: event_id.to_string(),
        sequence,
        occurred_at_utc: occurred_at_utc.to_string(),
        observed_at_utc: GENERATED_AT.to_string(),
        event_type: event_type.to_string(),
        actor: "AmberOsprey".to_string(),
        source_ref: source_ref.to_string(),
        source_hash: None,
        redaction_state: "none".to_string(),
        uncertainty: SwarmReplayEventUncertainty {
            state: "certain".to_string(),
            reasons: Vec::new(),
            suppressed_claims: Vec::new(),
        },
        payload,
    }
}

fn replay_event_with_actor(
    actor: &str,
    event_id: &str,
    sequence: u64,
    occurred_at_utc: &str,
    event_type: &str,
    source_ref: &str,
    payload: Value,
) -> SwarmReplayEvent {
    let mut event = replay_event(
        event_id,
        sequence,
        occurred_at_utc,
        event_type,
        source_ref,
        payload,
    );
    event.actor = actor.to_string();
    event
}

fn uncertain_replay_event(
    event_id: &str,
    sequence: u64,
    event_type: &str,
    source_ref: &str,
    reasons: &[&str],
    suppressed_claims: &[&str],
    payload: Value,
) -> SwarmReplayEvent {
    let mut event = replay_event(
        event_id,
        sequence,
        "2026-05-13T18:00:00Z",
        event_type,
        source_ref,
        payload,
    );
    event.uncertainty = SwarmReplayEventUncertainty {
        state: "missing_source".to_string(),
        reasons: reasons.iter().map(ToString::to_string).collect(),
        suppressed_claims: suppressed_claims.iter().map(ToString::to_string).collect(),
    };
    event
}

fn trace_from_events(events: Vec<SwarmReplayEvent>) -> SwarmReplayTrace {
    SwarmReplayTrace {
        schema: SWARM_REPLAY_TRACE_SCHEMA.to_string(),
        trace_id: "engine-fixture".to_string(),
        generated_at: GENERATED_AT.to_string(),
        contract_version: "1.0.0".to_string(),
        source_inventory: Vec::new(),
        ordering: SwarmReplayOrdering {
            monotonic_sequence_required: true,
            timestamp_normalization: "utc_rfc3339_z".to_string(),
            tie_breakers: vec![
                "sequence".to_string(),
                "source_ref".to_string(),
                "event_id".to_string(),
            ],
        },
        events,
        redaction_summary: SwarmReplayRedactionSummary {
            redacted_count: 0,
            sensitive_omitted_count: 0,
            raw_secret_bytes_emitted: 0,
            redacted_fields: Vec::new(),
        },
        uncertainty_summary: SwarmReplayUncertaintySummary {
            missing_sources: Vec::new(),
            malformed_sources: Vec::new(),
            stale_sources: Vec::new(),
            suppressed_claims: Vec::new(),
            event_count_by_uncertainty: std::collections::BTreeMap::default(),
        },
        replay_guards: SwarmReplayGuards {
            read_only: true,
            no_live_mutation: true,
            no_network_required: true,
            fail_closed_on_missing_required_sources: true,
            requires_source_inventory: true,
            disallowed_live_actions: Vec::new(),
        },
    }
}

fn diagnostic_codes(report: &pi::swarm_replay::SwarmReplayReport) -> BTreeSet<String> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn decision<'a>(
    decisions: &'a [SwarmReplayPolicyDecision],
    policy_id: &str,
    action: &str,
) -> Result<&'a SwarmReplayPolicyDecision, String> {
    decisions
        .iter()
        .find(|item| item.policy_id == policy_id && item.action == action)
        .ok_or_else(|| format!("missing policy decision {policy_id}/{action}"))
}

#[test]
fn clean_sources_normalize_into_contract_events() -> TestResult {
    let root = test_workspace("clean_sources")?;
    write_clean_sources(&root, true)?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    assert_eq!(trace.schema, SWARM_REPLAY_TRACE_SCHEMA);
    assert_eq!(trace.source_inventory.len(), 11);
    assert!(trace.replay_guards.read_only);
    assert!(trace.replay_guards.no_live_mutation);
    assert_eq!(trace.redaction_summary.raw_secret_bytes_emitted, 0);
    assert!(
        trace
            .redaction_summary
            .redacted_fields
            .iter()
            .any(|field| field.contains("body")),
        "agent mail body must be redacted"
    );

    let required_event_types = [
        "bead_lifecycle",
        "reservation_intent",
        "reservation_conflict",
        "agent_message",
        "build_slot_state",
        "rch_job_state",
        "cargo_gate_result",
        "worktree_state",
        "doctor_finding",
        "runpack_recommendation",
        "validation_artifact",
        "operator_handoff",
    ];
    let observed = event_types(&trace);
    for required in required_event_types {
        assert!(
            observed.contains(required),
            "missing normalized event type {required}"
        );
    }
    assert_monotonic_sequence(&trace)
}

#[test]
fn missing_agent_mail_keeps_beads_rch_and_doctor_usable() -> TestResult {
    let root = test_workspace("missing_agent_mail")?;
    write_clean_sources(&root, false)?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let mail = source_row(&trace, "agent_mail_archive")?;
    assert_eq!(mail.availability, "unavailable");
    assert_eq!(mail.freshness_state, "missing");
    assert!(
        mail.uncertainty
            .iter()
            .any(|reason| reason == "source_missing")
    );

    let observed = event_types(&trace);
    assert!(observed.contains("bead_lifecycle"));
    assert!(observed.contains("rch_job_state"));
    assert!(observed.contains("doctor_finding"));
    assert!(
        trace
            .uncertainty_summary
            .suppressed_claims
            .iter()
            .any(|claim| claim == "mail_thread_completeness")
    );
    Ok(())
}

#[test]
fn malformed_rch_snapshot_suppresses_queue_claims() -> TestResult {
    let root = test_workspace("malformed_rch_snapshot")?;
    write_clean_sources(&root, true)?;
    write_text(&root, "docs/evidence/rch-queue-status.json", "{not-json")?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let rch = source_row(&trace, "rch_queue_status")?;
    assert_eq!(rch.availability, "malformed");
    assert_eq!(rch.freshness_state, "malformed");
    assert!(!event_types(&trace).contains("rch_job_state"));
    assert!(
        trace
            .uncertainty_summary
            .suppressed_claims
            .iter()
            .any(|claim| claim == "queue_depth")
    );
    Ok(())
}

#[test]
fn doctor_preflight_budget_profile_feeds_resource_timeline() -> TestResult {
    let root = test_workspace("doctor_preflight_resource_profile")?;
    write_clean_sources(&root, true)?;
    write_json(
        &root,
        "docs/evidence/doctor-swarm.json",
        &json!({
            "host_profile": {
                "profile_id": "doctor-64-core",
                "cpu_cores": 64,
                "memory_gib": 256,
                "numa_nodes": 4,
                "cgroup_cpu_quota": 48,
                "cgroup_memory_gib": 192,
                "max_agent_concurrency": 32,
                "max_tool_concurrency": 16,
                "extension_hostcall_lanes": 24,
                "rch_worker_slots": 8,
                "target_dir": "/data/tmp/pi_agent_rust_cargo/doctor/target",
                "target_free_gib": 512,
                "tmpdir": "/data/tmp/pi_agent_rust_cargo/doctor/tmp",
                "tmpdir_free_gib": 256,
                "numa_hint": "pin_rch_workers_by_socket",
                "created_at": "2026-05-13T18:05:00Z"
            },
            "findings": [{
                "finding_id": "resource_budget_loaded",
                "severity": "info",
                "surface": "resource_governor",
                "status": "observed",
                "created_at": "2026-05-13T18:05:30Z"
            }]
        }),
    )?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    assert!(event_types(&trace).contains("host_resource_profile"));

    let replay = replay_swarm_trace(&trace)?;
    let profile = replay
        .final_state
        .resource_budget
        .as_ref()
        .ok_or("missing resource budget")?;
    assert_eq!(profile.profile_id, "doctor-64-core");
    assert_eq!(profile.cpu_cores, Some(64));
    assert_eq!(profile.memory_gib, Some(256));
    assert_eq!(profile.numa_nodes, Some(4));
    assert_eq!(profile.rch_worker_slots, Some(8));
    assert_eq!(profile.numa_hint, "pin_rch_workers_by_socket");
    assert!(
        replay
            .resource_pressure_timeline
            .iter()
            .any(|snapshot| snapshot.profile_id.as_deref() == Some("doctor-64-core"))
    );
    Ok(())
}

#[test]
fn stale_runpack_is_classified_without_discarding_inventory() -> TestResult {
    let root = test_workspace("stale_runpack")?;
    write_clean_sources(&root, true)?;
    write_json(
        &root,
        "docs/evidence/swarm-operator-runpack.json",
        &json!({
            "freshness_state": "stale",
            "operator_handoff": {
                "handoff_id": "stale-handoff",
                "summary": "old runpack",
                "next_actions": ["refresh"],
                "evidence_paths": [],
                "created_at": "2026-05-13T18:08:00Z"
            }
        }),
    )?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let runpack = source_row(&trace, "operator_runpack")?;
    assert_eq!(runpack.availability, "stale");
    assert_eq!(runpack.freshness_state, "stale");
    assert!(
        trace
            .uncertainty_summary
            .stale_sources
            .iter()
            .any(|source| source == "operator_runpack")
    );
    Ok(())
}

#[test]
fn duplicate_source_event_ids_are_deduplicated_and_marked() -> TestResult {
    let root = test_workspace("duplicate_source_event_ids")?;
    write_clean_sources(&root, true)?;
    write_json(
        &root,
        "validation/records.json",
        &json!({
            "artifacts": [
                {
                    "artifact_path": "same.json",
                    "artifact_schema": "pi.test",
                    "verdict": "pass",
                    "command": "first",
                    "created_at": "2026-05-13T18:11:00Z"
                },
                {
                    "artifact_path": "same.json",
                    "artifact_schema": "pi.test",
                    "verdict": "pass",
                    "command": "second",
                    "created_at": "2026-05-13T18:11:00Z"
                }
            ]
        }),
    )?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let mut ids = BTreeSet::new();
    for event in &trace.events {
        assert!(
            ids.insert(event.event_id.clone()),
            "duplicate final event id {}",
            event.event_id
        );
    }
    assert!(trace.events.iter().any(|event| {
        event
            .uncertainty
            .reasons
            .iter()
            .any(|reason| reason == "duplicate_source_event_id_deduplicated")
    }));
    Ok(())
}

#[test]
fn checked_in_golden_trace_fixture_is_downstream_consumable() -> TestResult {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_TRACE);
    let raw = fs::read_to_string(path)?;
    let trace: SwarmReplayTrace = serde_json::from_str(&raw)?;

    assert_eq!(trace.schema, SWARM_REPLAY_TRACE_SCHEMA);
    assert_eq!(trace.contract_version, "1.0.0");
    assert_eq!(trace.source_inventory.len(), 11);
    assert!(trace.replay_guards.read_only);
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event_type == "bead_lifecycle")
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event_type == "validation_artifact")
    );
    assert_monotonic_sequence(&trace)
}

#[test]
fn replay_engine_orders_events_by_sequence_not_input_order() -> TestResult {
    let later = replay_event(
        "event-a",
        2,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-a",
            "to_status": "closed",
            "priority": 3,
            "assignee": "AmberOsprey"
        }),
    );
    let earlier = replay_event(
        "event-b",
        1,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-b",
            "to_status": "in_progress",
            "priority": 2,
            "assignee": "SilentReef"
        }),
    );

    let report_a = replay_swarm_trace(&trace_from_events(vec![later.clone(), earlier.clone()]))?;
    let report_b = replay_swarm_trace(&trace_from_events(vec![earlier, later]))?;
    let order_a = report_a
        .snapshots
        .iter()
        .map(|snapshot| snapshot.event_id.clone())
        .collect::<Vec<_>>();
    let order_b = report_b
        .snapshots
        .iter()
        .map(|snapshot| snapshot.event_id.clone())
        .collect::<Vec<_>>();

    assert_eq!(report_a.schema, SWARM_REPLAY_REPORT_SCHEMA);
    assert_eq!(order_a, ["event-b", "event-a"]);
    assert_eq!(order_a, order_b);
    assert_eq!(report_a.final_logical_clock, 2);
    assert_eq!(report_a.final_state.beads["bd-a"].status, "closed");
    Ok(())
}

#[test]
fn replay_engine_skips_duplicate_event_ids_deterministically() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "same-event",
            1,
            "2026-05-13T18:00:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-dup",
                "to_status": "in_progress",
                "priority": 3,
                "assignee": "AmberOsprey"
            }),
        ),
        replay_event(
            "same-event",
            2,
            "2026-05-13T18:01:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-dup",
                "to_status": "closed",
                "priority": 3,
                "assignee": "AmberOsprey"
            }),
        ),
    ]);

    let report = replay_swarm_trace(&trace)?;
    assert_eq!(report.replayed_event_count, 1);
    assert_eq!(report.final_state.beads["bd-dup"].status, "in_progress");
    assert!(diagnostic_codes(&report).contains("duplicate_event_id_skipped"));
    Ok(())
}

#[test]
fn replay_engine_preserves_logical_clock_for_out_of_order_timestamps() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "newer",
            1,
            "2026-05-13T18:02:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-time",
                "to_status": "open",
                "priority": 3,
                "assignee": "AmberOsprey"
            }),
        ),
        replay_event(
            "older",
            2,
            "2026-05-13T18:01:00Z",
            "doctor_finding",
            "doctor_swarm_diagnostics",
            json!({
                "finding_id": "old-finding",
                "severity": "info",
                "surface": "swarm",
                "status": "observed"
            }),
        ),
    ]);

    let report = replay_swarm_trace(&trace)?;
    assert_eq!(report.snapshots[0].logical_clock, 1);
    assert_eq!(report.snapshots[1].logical_clock, 2);
    assert!(diagnostic_codes(&report).contains("event_timestamp_regressed"));
    Ok(())
}

#[test]
fn replay_engine_flags_missing_and_impossible_reservation_releases() -> TestResult {
    let missing_release = trace_from_events(vec![replay_event(
        "reservation-active",
        1,
        "2026-05-13T18:00:00Z",
        "reservation_intent",
        "agent_mail_archive",
        json!({
            "reservation_id": "res-1",
            "holder": "AmberOsprey",
            "path_patterns": ["src/swarm_replay.rs"],
            "exclusive": true,
            "state": "active"
        }),
    )]);
    let missing_release_report = replay_swarm_trace(&missing_release)?;
    assert!(
        diagnostic_codes(&missing_release_report).contains("reservation_missing_release_event")
    );

    let impossible_release = trace_from_events(vec![replay_event(
        "reservation-release",
        1,
        "2026-05-13T18:00:00Z",
        "reservation_intent",
        "agent_mail_archive",
        json!({
            "reservation_id": "res-2",
            "holder": "AmberOsprey",
            "path_patterns": ["src/swarm_replay.rs"],
            "exclusive": true,
            "state": "released"
        }),
    )]);
    let impossible_release_report = replay_swarm_trace(&impossible_release)?;
    assert!(
        diagnostic_codes(&impossible_release_report).contains("impossible_reservation_release")
    );
    assert!(!impossible_release_report.final_state.reservations["res-2"].active);
    Ok(())
}

#[test]
fn replay_engine_classifies_stale_rch_progress_and_negative_queue_depth() -> TestResult {
    let mut event = replay_event(
        "rch-stale",
        1,
        "2026-05-13T18:00:00Z",
        "rch_job_state",
        "rch_queue_status",
        json!({
            "job_id": "rch-1",
            "state": "running",
            "worker": "worker-1",
            "command": "rch exec -- cargo check --all-targets",
            "queue_position": -1
        }),
    );
    event.uncertainty = SwarmReplayEventUncertainty {
        state: "partial".to_string(),
        reasons: vec!["source_stale".to_string()],
        suppressed_claims: vec!["queue_depth".to_string()],
    };

    let report = replay_swarm_trace(&trace_from_events(vec![event]))?;
    let codes = diagnostic_codes(&report);
    assert!(codes.contains("rch_progress_from_uncertain_source"));
    assert!(codes.contains("negative_rch_queue_position"));
    assert!(report.final_state.rch_jobs["rch-1"].stale_progress);
    Ok(())
}

#[test]
fn replay_engine_requires_explicit_bead_reopen_evidence() -> TestResult {
    let closed = replay_event(
        "closed",
        1,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-reopen",
            "to_status": "closed",
            "priority": 3,
            "assignee": "AmberOsprey"
        }),
    );
    let implicit_reopen = replay_event(
        "implicit-reopen",
        2,
        "2026-05-13T18:01:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-reopen",
            "to_status": "open",
            "priority": 3,
            "assignee": "AmberOsprey"
        }),
    );
    let implicit_report =
        replay_swarm_trace(&trace_from_events(vec![closed.clone(), implicit_reopen]))?;
    assert!(
        diagnostic_codes(&implicit_report).contains("closed_bead_reopened_without_explicit_reopen")
    );

    let explicit_reopen = replay_event(
        "explicit-reopen",
        2,
        "2026-05-13T18:01:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-reopen",
            "to_status": "open",
            "priority": 3,
            "assignee": "AmberOsprey",
            "reopen": true
        }),
    );
    let explicit_report = replay_swarm_trace(&trace_from_events(vec![closed, explicit_reopen]))?;
    assert!(
        !diagnostic_codes(&explicit_report)
            .contains("closed_bead_reopened_without_explicit_reopen")
    );
    assert_eq!(
        explicit_report.final_state.beads["bd-reopen"].status,
        "open"
    );
    Ok(())
}

#[test]
fn replay_engine_classifies_agent_mail_outage_without_live_mail() -> TestResult {
    let event = uncertain_replay_event(
        "missing-mail",
        1,
        "agent_message",
        "agent_mail_archive",
        &["source_missing"],
        &["mail_thread_completeness", "active_reservation_holder"],
        json!({
            "thread_id": "unknown",
            "sender": "unknown",
            "recipients": [],
            "importance": "unknown",
            "ack_required": false
        }),
    );

    let report = replay_swarm_trace(&trace_from_events(vec![event]))?;
    assert!(!report.final_state.coordination.agent_mail_available);
    assert!(report.final_state.coordination.missing_agent_mail_evidence);
    assert!(diagnostic_codes(&report).contains("agent_mail_source_unavailable"));
    assert!(report.replay_guards.consumed_trace_only);
    Ok(())
}

#[test]
fn policy_runner_is_deterministic_and_advisory_only() -> TestResult {
    let trace = trace_from_events(vec![replay_event(
        "ready-bead",
        1,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-ready",
            "to_status": "open",
            "priority": 3,
            "assignee": "unassigned"
        }),
    )]);
    let replay = replay_swarm_trace(&trace)?;
    let policies = default_swarm_replay_baseline_policies();

    let first = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;
    let second = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;

    assert_eq!(first, second);
    assert_eq!(first.schema, SWARM_REPLAY_POLICY_REPORT_SCHEMA);
    assert!(first.policy_guards.advisory_only);
    assert!(first.policy_guards.no_live_mutation);
    assert!(first.policy_guards.no_network_required);
    assert!(first.policy_guards.consumed_replay_report_only);
    assert_eq!(
        first.policy_ids,
        [
            "build_slot_protective",
            "conservative_manual",
            "existing_autopilot",
            "rch_fanout_limited",
            "stale_bead_reclaiming"
        ]
    );
    assert!(first.decisions.iter().all(|item| item.advisory_only));
    assert!(
        first
            .decisions
            .iter()
            .all(|item| !item.reason_codes.is_empty())
    );
    assert!(
        first
            .decisions
            .iter()
            .all(|item| !item.source_evidence.is_empty())
    );
    Ok(())
}

#[test]
fn policy_report_includes_golden_comparison_metrics() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "ready-bead",
            1,
            "2026-05-13T18:00:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-compare",
                "to_status": "open",
                "priority": 2,
                "assignee": "unassigned"
            }),
        ),
        replay_event(
            "reservation-conflict",
            2,
            "2026-05-13T18:02:00Z",
            "reservation_conflict",
            "agent_mail_archive",
            json!({
                "path_pattern": "src/swarm_replay.rs",
                "holder": "OtherAgent",
                "conflict_reason": "active exclusive lease"
            }),
        ),
        replay_event(
            "rch-queued",
            3,
            "2026-05-13T18:05:00Z",
            "rch_job_state",
            "rch_queue_status",
            json!({
                "job_id": "rch-queued",
                "state": "queued",
                "worker": "worker-1",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 3
            }),
        ),
        replay_event(
            "operator-handoff",
            4,
            "2026-05-13T18:09:00Z",
            "operator_handoff",
            "operator_runpack",
            json!({
                "handoff_id": "handoff-compare",
                "summary": "continue via beads while mail is unavailable",
                "next_actions": ["continue bd-compare"],
                "evidence_paths": ["docs/evidence/swarm-operator-runpack.json"]
            }),
        ),
        replay_event(
            "closed-bead",
            5,
            "2026-05-13T18:14:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-compare",
                "to_status": "closed",
                "priority": 2,
                "assignee": "Codex"
            }),
        ),
    ]);
    let replay = replay_swarm_trace(&trace)?;
    let policies = [
        SwarmReplayBaselinePolicy::ConservativeManual,
        SwarmReplayBaselinePolicy::ExistingAutopilot,
        SwarmReplayBaselinePolicy::RchFanoutLimited,
    ];
    let report = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;

    assert_eq!(report.comparison_count, 3);
    assert_eq!(
        report
            .policy_comparisons
            .iter()
            .map(|row| row.policy_id.as_str())
            .collect::<Vec<_>>(),
        [
            "existing_autopilot",
            "rch_fanout_limited",
            "conservative_manual"
        ]
    );

    let observed = serde_json::to_value(&report.policy_comparisons)?;
    let expected =
        load_json("tests/golden_corpus/swarm_replay_trace/policy_comparison_metrics.json")?;
    assert_eq!(observed, expected);
    Ok(())
}

#[test]
fn policy_comparison_suppresses_latency_when_timestamps_are_missing() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "missing-time",
            1,
            "not-a-timestamp",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-missing-time",
                "to_status": "open",
                "priority": 2,
                "assignee": "unassigned"
            }),
        ),
        replay_event(
            "normal-time",
            2,
            "2026-05-13T18:01:00Z",
            "rch_job_state",
            "rch_queue_status",
            json!({
                "job_id": "rch-missing-time",
                "state": "queued",
                "worker": "worker-1",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 2
            }),
        ),
    ]);
    let replay = replay_swarm_trace(&trace)?;
    let report = evaluate_swarm_replay_baseline_policies(
        &replay,
        &[SwarmReplayBaselinePolicy::RchFanoutLimited],
    )?;
    let comparison = report
        .policy_comparisons
        .iter()
        .find(|row| row.policy_id == "rch_fanout_limited")
        .ok_or("missing rch comparison")?;

    assert_eq!(comparison.metrics.blocked_time_minutes, None);
    assert_eq!(comparison.metrics.average_wait_minutes, None);
    assert_eq!(comparison.metrics.p95_wait_minutes, None);
    assert!(
        comparison
            .missing_data
            .iter()
            .any(|missing| missing.claim == "latency_claims")
    );
    assert!(
        comparison
            .confidence
            .reasons
            .contains(&"missing_data_suppressed_claims".to_string())
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ResourceProfileFixture<'a> {
    profile_id: &'a str,
    cpu_cores: u64,
    memory_gib: u64,
    target_free_gib: u64,
    tmpdir_free_gib: u64,
    extension_hostcall_lanes: u64,
    rch_worker_slots: u64,
    numa_hint: &'a str,
}

fn resource_profile_payload(profile: ResourceProfileFixture<'_>) -> Value {
    json!({
        "profile_id": profile.profile_id,
        "cpu_cores": profile.cpu_cores,
        "memory_gib": profile.memory_gib,
        "numa_nodes": if profile.memory_gib >= 256 { 4 } else { 1 },
        "cgroup_cpu_quota": profile.cpu_cores,
        "cgroup_memory_gib": profile.memory_gib,
        "max_agent_concurrency": profile.extension_hostcall_lanes,
        "max_tool_concurrency": profile.rch_worker_slots,
        "extension_hostcall_lanes": profile.extension_hostcall_lanes,
        "rch_worker_slots": profile.rch_worker_slots,
        "target_dir": format!("/data/tmp/pi_agent_rust_cargo/{}/target", profile.profile_id),
        "target_free_gib": profile.target_free_gib,
        "tmpdir": format!("/data/tmp/pi_agent_rust_cargo/{}/tmp", profile.profile_id),
        "tmpdir_free_gib": profile.tmpdir_free_gib,
        "numa_hint": profile.numa_hint
    })
}

fn pressure_trace_for_profile(profile: Value) -> SwarmReplayTrace {
    trace_from_events(vec![
        replay_event(
            "resource-profile",
            1,
            "2026-05-13T18:00:00Z",
            "host_resource_profile",
            "synthetic_host_profile",
            profile,
        ),
        replay_event_with_actor(
            "AgentOne",
            "agent-one",
            2,
            "2026-05-13T18:01:00Z",
            "agent_message",
            "agent_mail_archive",
            json!({
                "thread_id": "bd-resource",
                "sender": "AgentOne",
                "recipients": ["AgentTwo"],
                "importance": "normal",
                "ack_required": false
            }),
        ),
        replay_event_with_actor(
            "AgentTwo",
            "agent-two",
            3,
            "2026-05-13T18:02:00Z",
            "agent_message",
            "agent_mail_archive",
            json!({
                "thread_id": "bd-resource",
                "sender": "AgentTwo",
                "recipients": ["AgentThree"],
                "importance": "normal",
                "ack_required": false
            }),
        ),
        replay_event_with_actor(
            "AgentThree",
            "agent-three",
            4,
            "2026-05-13T18:03:00Z",
            "agent_message",
            "agent_mail_archive",
            json!({
                "thread_id": "bd-resource",
                "sender": "AgentThree",
                "recipients": ["AgentOne"],
                "importance": "normal",
                "ack_required": false
            }),
        ),
        replay_event(
            "build-slot",
            5,
            "2026-05-13T18:04:00Z",
            "build_slot_state",
            "agent_mail_archive",
            json!({
                "slot": "cargo-all-targets",
                "holder": "AgentOne",
                "state": "active",
                "expires_at_utc": "2026-05-13T19:00:00Z"
            }),
        ),
        replay_event(
            "rch-queued",
            6,
            "2026-05-13T18:05:00Z",
            "rch_job_state",
            "rch_queue_status",
            json!({
                "job_id": "rch-pressure",
                "state": "queued",
                "worker": "worker-1",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 3
            }),
        ),
    ])
}

#[test]
fn resource_budget_profiles_model_small_ci_large_hosts() -> TestResult {
    let small = replay_swarm_trace(&pressure_trace_for_profile(resource_profile_payload(
        ResourceProfileFixture {
            profile_id: "small-laptop",
            cpu_cores: 4,
            memory_gib: 8,
            target_free_gib: 8,
            tmpdir_free_gib: 8,
            extension_hostcall_lanes: 2,
            rch_worker_slots: 1,
            numa_hint: "single_socket",
        },
    )))?;
    let small_peak = small
        .resource_pressure_timeline
        .last()
        .ok_or("missing small peak")?;
    assert_eq!(small_peak.cpu_pressure, "saturated");
    assert_eq!(small_peak.memory_pressure, "saturated");
    assert_eq!(small_peak.tmpdir_pressure, "saturated");
    assert_eq!(small_peak.target_dir_pressure, "saturated");
    assert_eq!(small_peak.rch_worker_pressure, "saturated");
    assert_eq!(small_peak.extension_lane_pressure, "saturated");
    assert!(
        small_peak
            .saturation_reasons
            .contains(&"cpu_saturated".to_string())
    );

    let ci = replay_swarm_trace(&pressure_trace_for_profile(resource_profile_payload(
        ResourceProfileFixture {
            profile_id: "default-ci",
            cpu_cores: 8,
            memory_gib: 16,
            target_free_gib: 64,
            tmpdir_free_gib: 64,
            extension_hostcall_lanes: 4,
            rch_worker_slots: 4,
            numa_hint: "shared_runner",
        },
    )))?;
    let ci_peak = ci
        .resource_pressure_timeline
        .last()
        .ok_or("missing ci peak")?;
    assert_eq!(ci_peak.cpu_pressure, "saturated");
    assert_eq!(ci_peak.memory_pressure, "high");
    assert_eq!(ci_peak.tmpdir_pressure, "low");
    assert_eq!(ci_peak.target_dir_pressure, "low");
    assert_eq!(ci_peak.rch_worker_pressure, "high");

    let large_64 = replay_swarm_trace(&pressure_trace_for_profile(resource_profile_payload(
        ResourceProfileFixture {
            profile_id: "large-64-core",
            cpu_cores: 64,
            memory_gib: 128,
            target_free_gib: 256,
            tmpdir_free_gib: 256,
            extension_hostcall_lanes: 16,
            rch_worker_slots: 8,
            numa_hint: "spread_agents_across_sockets",
        },
    )))?;
    let large_peak = large_64
        .resource_pressure_timeline
        .last()
        .ok_or("missing large peak")?;
    assert_eq!(large_peak.cpu_pressure, "low");
    assert_eq!(large_peak.memory_pressure, "low");
    assert_eq!(large_peak.rch_worker_pressure, "low");

    let huge = replay_swarm_trace(&pressure_trace_for_profile(resource_profile_payload(
        ResourceProfileFixture {
            profile_id: "huge-256gb",
            cpu_cores: 64,
            memory_gib: 256,
            target_free_gib: 512,
            tmpdir_free_gib: 512,
            extension_hostcall_lanes: 32,
            rch_worker_slots: 16,
            numa_hint: "pin_rch_workers_by_socket",
        },
    )))?;
    let huge_profile = huge
        .final_state
        .resource_budget
        .as_ref()
        .ok_or("missing huge profile")?;
    assert_eq!(huge_profile.memory_gib, Some(256));
    assert_eq!(huge_profile.numa_nodes, Some(4));
    assert_eq!(huge_profile.numa_hint, "pin_rch_workers_by_socket");
    assert!(
        huge.resource_pressure_timeline
            .iter()
            .all(|snapshot| snapshot.saturation_reasons.is_empty())
    );
    Ok(())
}

#[test]
fn policy_comparison_suppresses_resource_claims_without_host_facts() -> TestResult {
    let trace = trace_from_events(vec![replay_event(
        "ready-bead",
        1,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-no-host-facts",
            "to_status": "open",
            "priority": 2,
            "assignee": "unassigned"
        }),
    )]);
    let replay = replay_swarm_trace(&trace)?;
    let report = evaluate_swarm_replay_baseline_policies(
        &replay,
        &[SwarmReplayBaselinePolicy::ExistingAutopilot],
    )?;
    let comparison = report
        .policy_comparisons
        .iter()
        .find(|row| row.policy_id == "existing_autopilot")
        .ok_or("missing autopilot comparison")?;

    assert_eq!(comparison.metrics.resource_budget.profile_id, None);
    assert_eq!(comparison.metrics.resource_budget.cpu_pressure, "unknown");
    assert!(comparison.missing_data.iter().any(|missing| {
        missing.claim == "resource_budget_claims"
            && missing
                .reasons
                .contains(&"host resource profile missing".to_string())
    }));
    Ok(())
}

#[test]
fn baseline_policies_disagree_when_agent_mail_is_unavailable() -> TestResult {
    let trace = trace_from_events(vec![
        uncertain_replay_event(
            "missing-mail",
            1,
            "agent_message",
            "agent_mail_archive",
            &["source_missing"],
            &["mail_thread_completeness"],
            json!({
                "thread_id": "unknown",
                "sender": "unknown",
                "recipients": [],
                "importance": "unknown",
                "ack_required": false
            }),
        ),
        replay_event(
            "ready-bead",
            2,
            "2026-05-13T18:01:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-mail-red",
                "to_status": "open",
                "priority": 2,
                "assignee": "unassigned"
            }),
        ),
    ]);
    let replay = replay_swarm_trace(&trace)?;
    let policies = [
        SwarmReplayBaselinePolicy::ConservativeManual,
        SwarmReplayBaselinePolicy::ExistingAutopilot,
        SwarmReplayBaselinePolicy::StaleBeadReclaiming,
    ];
    let report = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;

    let manual = decision(&report.decisions, "conservative_manual", "handoff")?;
    assert_eq!(manual.target_id, "agent_mail");
    assert!(
        manual
            .reason_codes
            .contains(&"agent_mail_unavailable_requires_manual_coordination".to_string())
    );

    let autopilot = decision(&report.decisions, "existing_autopilot", "claim_bead")?;
    assert_eq!(autopilot.target_id, "bd-mail-red");
    assert!(autopilot.would_require_live_mutation);
    assert!(
        autopilot
            .reason_codes
            .contains(&"agent_mail_unavailable_continue_via_beads".to_string())
    );

    let reclaiming = decision(
        &report.decisions,
        "stale_bead_reclaiming",
        "refresh_evidence",
    )?;
    assert_eq!(reclaiming.target_id, "agent_mail");
    assert!(!reclaiming.would_require_live_mutation);
    Ok(())
}

#[test]
fn baseline_policies_disagree_under_rch_queue_pressure() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "ready-bead",
            1,
            "2026-05-13T18:00:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-rch-pressure",
                "to_status": "open",
                "priority": 2,
                "assignee": "unassigned"
            }),
        ),
        replay_event(
            "rch-queued",
            2,
            "2026-05-13T18:01:00Z",
            "rch_job_state",
            "rch_queue_status",
            json!({
                "job_id": "rch-queued",
                "state": "queued",
                "worker": "worker-1",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 4
            }),
        ),
    ]);
    let replay = replay_swarm_trace(&trace)?;
    let policies = [
        SwarmReplayBaselinePolicy::ExistingAutopilot,
        SwarmReplayBaselinePolicy::RchFanoutLimited,
        SwarmReplayBaselinePolicy::BuildSlotProtective,
    ];
    let report = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;

    let autopilot = decision(&report.decisions, "existing_autopilot", "claim_bead")?;
    assert_eq!(autopilot.target_id, "bd-rch-pressure");

    let limited = decision(&report.decisions, "rch_fanout_limited", "back_off_cargo")?;
    assert_eq!(limited.target_id, "rch-queued");
    assert!(
        limited
            .reason_codes
            .contains(&"rch_queue_position_positive".to_string())
    );

    let protective = decision(&report.decisions, "build_slot_protective", "back_off_cargo")?;
    assert_eq!(protective.target_id, "rch-queued");
    assert!(
        protective
            .reason_codes
            .contains(&"rch_pressure_protects_build_capacity".to_string())
    );
    Ok(())
}

#[test]
fn baseline_policies_disagree_under_dirty_worktree_contention() -> TestResult {
    let trace = trace_from_events(vec![
        replay_event(
            "dirty-worktree",
            1,
            "2026-05-13T18:00:00Z",
            "worktree_state",
            "git_refs",
            json!({
                "head": "abc123",
                "branch": "main",
                "dirty": true,
                "changed_paths": ["tests/release_evidence_gate.rs"]
            }),
        ),
        replay_event(
            "ready-bead",
            2,
            "2026-05-13T18:01:00Z",
            "bead_lifecycle",
            "beads_jsonl",
            json!({
                "bead_id": "bd-dirty",
                "to_status": "open",
                "priority": 3,
                "assignee": "unassigned"
            }),
        ),
    ]);
    let replay = replay_swarm_trace(&trace)?;
    let policies = default_swarm_replay_baseline_policies();
    let report = evaluate_swarm_replay_baseline_policies(&replay, &policies)?;

    let worktree = replay
        .final_state
        .worktree
        .as_ref()
        .ok_or("missing worktree")?;
    assert!(worktree.dirty);
    assert_eq!(worktree.changed_paths, ["tests/release_evidence_gate.rs"]);

    assert!(
        decision(&report.decisions, "conservative_manual", "wait")?
            .reason_codes
            .contains(&"dirty_worktree_requires_manual_review".to_string())
    );
    assert!(
        decision(&report.decisions, "existing_autopilot", "wait")?
            .reason_codes
            .contains(&"dirty_worktree_contention".to_string())
    );
    assert!(
        decision(&report.decisions, "rch_fanout_limited", "wait")?
            .reason_codes
            .contains(&"dirty_worktree_avoid_validation_fanout".to_string())
    );
    assert_eq!(
        decision(&report.decisions, "stale_bead_reclaiming", "claim_bead")?.target_id,
        "bd-dirty"
    );
    Ok(())
}

#[test]
fn stale_bead_reclaiming_flags_absent_assignee() -> TestResult {
    let trace = trace_from_events(vec![replay_event(
        "stale-bead",
        1,
        "2026-05-13T18:00:00Z",
        "bead_lifecycle",
        "beads_jsonl",
        json!({
            "bead_id": "bd-stale",
            "to_status": "in_progress",
            "priority": 1,
            "assignee": "LongGoneAgent"
        }),
    )]);
    let replay = replay_swarm_trace(&trace)?;
    let report = evaluate_swarm_replay_baseline_policies(
        &replay,
        &[SwarmReplayBaselinePolicy::StaleBeadReclaiming],
    )?;

    let reclaim = decision(
        &report.decisions,
        "stale_bead_reclaiming",
        "reclaim_stale_bead",
    )?;
    assert_eq!(reclaim.target_id, "bd-stale");
    assert!(reclaim.would_require_live_mutation);
    assert!(
        reclaim
            .reason_codes
            .contains(&"in_progress_assignee_absent_from_replay_agents".to_string())
    );
    Ok(())
}
