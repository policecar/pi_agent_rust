#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/swarm-progress-slo-contract.json";
const EXPECTED_CONTRACT_SCHEMA: &str = "pi.swarm.progress_slo_contract.v1";
const EXPECTED_PROGRESS_SCHEMA: &str = "pi.swarm.progress_slo.v1";
const EXPECTED_BEAD_ID: &str = "bd-wzri8.1";
const EXPECTED_PARENT_BEAD_ID: &str = "bd-wzri8";

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "beads_active_delta",
    "beads_closed_delta",
    "git_commit_delta",
    "rch_posture",
    "validation_broker_posture",
    "agent_mail_health",
    "operator_runpack_summary",
    "swarm_autopilot_summary",
    "context_intelligence_summary",
    "operator_time_window",
];

const REQUIRED_SOURCE_CLASSES: &[&str] = &[
    "beads_active_closed_delta",
    "git_commit_delta",
    "rch_and_validation_broker_posture",
    "agent_mail_health",
    "runpack_autopilot_context_summaries",
    "operator_provided_time_window",
];

const REQUIRED_STATUSES: &[&str] = &[
    "progressing",
    "quiet_blocked",
    "coordination_degraded",
    "build_saturated",
    "stalled",
    "converged_no_open_work",
    "malformed_source_degraded",
    "insufficient_evidence_degraded",
];

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Result<Value, String> {
    let path = repo_root().join(CONTRACT_PATH);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn pointer<'a>(value: &'a Value, path: &str) -> Result<&'a Value, String> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> Result<&'a str, String> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn pointer_bool(value: &Value, path: &str) -> Result<bool, String> {
    pointer(value, path)?
        .as_bool()
        .ok_or_else(|| format!("{path} must be a bool"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], String> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn non_empty_string_set<'a>(value: &'a Value, path: &str) -> Result<HashSet<&'a str>, String> {
    let mut entries = HashSet::new();
    let non_string_message = format!("{path} entries must be strings");
    let blank_message = format!("{path} entries must be non-empty");
    for entry in pointer_array(value, path)? {
        let Some(raw) = entry.as_str() else {
            return Err(non_string_message);
        };
        let normalized = raw.trim();
        if normalized.is_empty() {
            return Err(blank_message);
        }
        entries.insert(normalized);
    }
    Ok(entries)
}

fn require_set(value: &Value, path: &str, required: &[&str], label: &str) -> TestResult {
    let observed = non_empty_string_set(value, path)?;
    if let Some(missing) = required.iter().find(|item| !observed.contains(**item)) {
        return Err(format!("missing {label}: {missing}"));
    }
    Ok(())
}

fn require_array_contains_fragment(value: &Value, path: &str, fragment: &str) -> TestResult {
    require(
        pointer_array(value, path)?
            .iter()
            .any(|entry| entry.as_str().is_some_and(|text| text.contains(fragment))),
        format!("{path} must contain fragment {fragment:?}"),
    )
}

fn boundary_ids(contract: &Value) -> Result<HashSet<&str>, String> {
    let mut ids = HashSet::new();
    for boundary in pointer_array(contract, "/authoritative_source_boundaries")? {
        let source_id = pointer_str(boundary, "/source_id")?;
        require(ids.insert(source_id), "duplicate source boundary")?;
        require(
            !pointer_array(boundary, "/authoritative_for")?.is_empty(),
            "source boundary must name authoritative facts",
        )?;
        let boundary_text = pointer_str(boundary, "/progress_slo_boundary")?;
        require(
            boundary_text.contains("must not"),
            "source boundary must declare a negative authority boundary",
        )?;
    }
    Ok(ids)
}

#[test]
fn progress_slo_contract_has_identity_and_advisory_purpose() -> TestResult {
    let contract = load_contract()?;

    require(
        pointer_str(&contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/progress_slo_schema")? == EXPECTED_PROGRESS_SCHEMA,
        "progress SLO schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/bead_id")? == EXPECTED_BEAD_ID,
        "bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/parent_bead_id")? == EXPECTED_PARENT_BEAD_ID,
        "parent bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/purpose")?
            == "read_only_swarm_progress_slo_advisory_not_source_of_truth",
        "purpose must keep progress SLO advisory",
    )?;
    require_array_contains_fragment(&contract, "/non_goals", "replace_beads")?;
    require_array_contains_fragment(&contract, "/non_goals", "perform_live_mutation")?;
    require_array_contains_fragment(&contract, "/non_goals", "dropin_certification")
}

#[test]
fn progress_slo_contract_declares_required_sources_and_boundaries() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/source_inventory_contract/required_source_ids",
        REQUIRED_SOURCE_IDS,
        "source id",
    )?;
    require_set(
        &contract,
        "/source_inventory_contract/required_source_classes",
        REQUIRED_SOURCE_CLASSES,
        "source class",
    )?;
    require_set(
        &contract,
        "/source_inventory_contract/required_source_fields",
        &[
            "source_id",
            "source_class",
            "source_kind",
            "path",
            "availability",
            "freshness_state",
            "observed_at_utc",
            "source_hash",
            "authoritative_for",
            "redaction_state",
            "degraded_reasons",
            "suppressed_claims",
        ],
        "source field",
    )?;
    require_set(
        &contract,
        "/source_inventory_contract/allowed_availability",
        &[
            "available",
            "unavailable",
            "partial",
            "malformed",
            "stale",
            "not_configured",
        ],
        "availability state",
    )?;
    require_set(
        &contract,
        "/source_inventory_contract/allowed_freshness_states",
        &[
            "current",
            "stale",
            "missing",
            "malformed",
            "freshness_unknown",
        ],
        "freshness state",
    )?;

    let ids = boundary_ids(&contract)?;
    if let Some(missing) = REQUIRED_SOURCE_IDS
        .iter()
        .find(|source_id| !ids.contains(**source_id))
    {
        return Err(format!("missing source boundary for {missing}"));
    }

    Ok(())
}

#[test]
fn progress_slo_contract_fails_closed_for_missing_or_malformed_sources() -> TestResult {
    let contract = load_contract()?;

    let policy = pointer_str(
        &contract,
        "/source_inventory_contract/missing_or_malformed_source_policy",
    )?;
    require(
        policy.contains("must not infer progress facts"),
        "missing source policy must forbid invented progress facts",
    )?;
    require(
        policy.contains("must not become progressing"),
        "missing source policy must block progressing status",
    )?;
    require(
        pointer_bool(&contract, "/fail_closed_policy/fail_closed")?,
        "fail-closed policy must be enabled",
    )?;
    require(
        pointer_str(
            &contract,
            "/fail_closed_policy/malformed_required_source_status",
        )? == "malformed_source_degraded",
        "malformed sources must degrade",
    )?;
    require(
        pointer_str(
            &contract,
            "/fail_closed_policy/missing_required_authority_status",
        )? == "insufficient_evidence_degraded",
        "missing authority must degrade",
    )?;
    require_set(
        &contract,
        "/fail_closed_policy/green_status_forbidden_when",
        &[
            "operator_time_window_missing_or_malformed",
            "beads_delta_missing_or_malformed",
            "git_delta_missing_or_malformed",
            "required_source_freshness_unknown",
            "redaction_state_unsafe_to_emit",
            "source_statuses_empty",
        ],
        "green-forbidden condition",
    )
}

#[test]
fn progress_slo_contract_locks_statuses_reasons_and_metrics() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/required_progress_top_level_keys",
        &[
            "schema",
            "generated_at",
            "contract_version",
            "time_window",
            "status",
            "confidence",
            "reason_ids",
            "source_statuses",
            "progress_metrics",
            "saturation_summary",
            "redaction_summary",
            "suppressed_claims",
            "next_actions",
        ],
        "top-level progress key",
    )?;
    require_set(
        &contract,
        "/status_contract/allowed_statuses",
        REQUIRED_STATUSES,
        "status",
    )?;
    require_set(
        &contract,
        "/status_contract/required_reason_ids",
        &[
            "PROGRESS-SLO-BEAD-CLOSEOUT",
            "PROGRESS-SLO-GIT-COMMIT-DELTA",
            "PROGRESS-SLO-NO-READY-WORK",
            "PROGRESS-SLO-STALE-IN-PROGRESS",
            "PROGRESS-SLO-AGENT-MAIL-DEGRADED",
            "PROGRESS-SLO-RCH-SATURATED",
            "PROGRESS-SLO-VALIDATION-BROKER-SATURATED",
            "PROGRESS-SLO-MALFORMED-SOURCE",
            "PROGRESS-SLO-MISSING-AUTHORITY",
            "PROGRESS-SLO-CONVERGED-NO-OPEN-WORK",
        ],
        "reason id",
    )?;
    require_set(
        &contract,
        "/progress_metrics_contract/required_fields",
        &[
            "closed_beads",
            "open_beads",
            "in_progress_beads",
            "ready_beads",
            "commits",
            "pushed_commits",
            "validation_passes",
            "validation_failures",
            "agent_mail_health",
            "rch_queue_depth",
            "stale_in_progress_candidates",
        ],
        "progress metric",
    )?;

    let useful_progress_policy = pointer_str(
        &contract,
        "/progress_metrics_contract/useful_progress_policy",
    )?;
    require(
        useful_progress_policy.contains("File churn"),
        "useful progress policy must reject file churn as sufficient progress",
    )?;
    require(
        useful_progress_policy.contains("RCH queue activity"),
        "useful progress policy must reject build activity as sufficient progress",
    )
}

#[test]
fn progress_slo_contract_is_read_only_and_does_not_replace_existing_authorities() -> TestResult {
    let contract = load_contract()?;

    require(
        pointer_bool(&contract, "/progress_slo_guards/read_only")?,
        "progress SLO guard must be read-only",
    )?;
    require(
        pointer_bool(&contract, "/progress_slo_guards/no_live_mutation")?,
        "progress SLO guard must forbid live mutation",
    )?;
    require(
        pointer_bool(&contract, "/progress_slo_guards/advisory_only")?,
        "progress SLO guard must be advisory-only",
    )?;
    require_set(
        &contract,
        "/progress_slo_guards/disallowed_live_actions",
        &[
            "claim_bead",
            "close_bead",
            "reopen_bead",
            "create_bead",
            "reprioritize_bead",
            "send_agent_mail",
            "acknowledge_agent_mail",
            "reserve_file",
            "release_file",
            "start_rch_job",
            "cancel_rch_job",
            "git_commit",
            "git_push",
            "git_pull_rebase",
            "write_source_file",
            "delete_file",
        ],
        "disallowed live action",
    )?;
    for fragment in [
        "replace_beads",
        "replace_agent_mail",
        "replace_rch",
        "replace_doctor_runpacks_autopilot_or_context_intelligence",
        "replace_ci_ubs_beads_ledger_reconciliation_or_release_gates",
    ] {
        require_array_contains_fragment(&contract, "/non_goals", fragment)?;
    }
    require_set(
        &contract,
        "/downstream_dependencies/unblocked_beads",
        &["bd-wzri8.2", "bd-wzri8.8"],
        "downstream bead",
    )
}

#[test]
fn progress_slo_contract_declares_redaction_and_test_obligations() -> TestResult {
    let contract = load_contract()?;

    require(
        pointer_bool(&contract, "/redaction_policy/fail_closed")?,
        "redaction policy must fail closed",
    )?;
    require_set(
        &contract,
        "/redaction_policy/allowed_redaction_states",
        &["none", "redacted", "sensitive_omitted", "unsafe_to_emit"],
        "redaction state",
    )?;
    require_set(
        &contract,
        "/redaction_policy/forbidden_raw_fields",
        &[
            "prompt_body",
            "agent_mail_body",
            "api_key",
            "token",
            "credential",
            "secret",
            "raw_home_path",
            "raw_tmp_path",
            "session_transcript",
        ],
        "forbidden raw field",
    )?;
    require(
        pointer_str(&contract, "/contract_tests/required_test_file")?
            == "tests/swarm_progress_slo_contract.rs",
        "contract test path mismatch",
    )?;
    require(
        pointer_str(&contract, "/contract_tests/focused_command")?
            == "rch exec -- cargo test --test swarm_progress_slo_contract -- --nocapture",
        "focused command mismatch",
    )?;
    require_array_contains_fragment(&contract, "/contract_tests/must_prove", "source inventory")?;
    require_array_contains_fragment(&contract, "/contract_tests/must_prove", "fail closed")
}
