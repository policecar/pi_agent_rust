#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/context-intelligence-closeout-gate-contract.json";
const EVIDENCE_PATH: &str = "docs/evidence/context-intelligence-closeout-gate.json";
const EXPECTED_CONTRACT_SCHEMA: &str = "pi.context_intelligence.closeout_gate_contract.v1";
const EXPECTED_EVIDENCE_SCHEMA: &str = "pi.context_intelligence.closeout_gate.v1";
const EXPECTED_PURPOSE: &str =
    "prompt_to_artifact_context_intelligence_closeout_gate_not_source_of_truth";

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &str) -> Result<Value, String> {
    let full_path = repo_root().join(path);
    let raw = std::fs::read_to_string(&full_path)
        .map_err(|err| format!("failed to read {}: {err}", full_path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", full_path.display()))
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

fn string_set(value: &Value, path: &str) -> Result<HashSet<String>, String> {
    let mut entries = HashSet::new();
    for entry in pointer_array(value, path)? {
        let raw = entry
            .as_str()
            .ok_or_else(|| format!("{path} entries must be strings"))?;
        require(
            !raw.trim().is_empty(),
            format!("{path} entry must be non-empty"),
        )?;
        entries.insert(raw.to_string());
    }
    Ok(entries)
}

fn required_set(contract: &Value, path: &str) -> Result<HashSet<String>, String> {
    string_set(contract, path)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn require_hex_commit(value: &Value, path: &str) -> TestResult {
    let commit = pointer_str(value, path)?;
    require(
        is_hex_commit(commit),
        format!("{path} must be a 40-character hex commit, got {commit}"),
    )
}

fn require_non_empty_array(value: &Value, path: &str, label: &str) -> TestResult {
    require(
        !pointer_array(value, path)?.is_empty(),
        format!("{label} must not be empty"),
    )
}

fn checklist_row<'a>(evidence: &'a Value, id: &str) -> Result<&'a Value, String> {
    pointer_array(evidence, "/checklist")?
        .iter()
        .find(|row| row.pointer("/id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("missing checklist row {id}"))
}

#[test]
fn context_intelligence_closeout_contract_and_evidence_have_expected_identity() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;

    require(
        pointer_str(&contract, "/schema")? == EXPECTED_CONTRACT_SCHEMA,
        "contract schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/decision_gate_schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "contract decision_gate_schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/purpose")? == EXPECTED_PURPOSE,
        "contract purpose mismatch",
    )?;
    require(
        pointer_str(&evidence, "/schema")? == EXPECTED_EVIDENCE_SCHEMA,
        "evidence schema mismatch",
    )?;
    require(
        pointer_str(&evidence, "/purpose")? == EXPECTED_PURPOSE,
        "evidence purpose mismatch",
    )?;
    require(
        pointer_str(&evidence, "/status")? == "pass",
        "evidence status must be pass",
    )?;
    require(
        pointer_str(&evidence, "/parent_epic/id")? == "bd-ircr3",
        "parent epic id mismatch",
    )?;
    require(
        pointer_str(&evidence, "/final_gate_bead/id")? == "bd-ircr3.11",
        "final gate bead id mismatch",
    )?;
    require(
        pointer_bool(&evidence, "/epic_can_close_after_this_commit")?,
        "passing closeout gate must allow parent close after the commit lands",
    )?;

    for key in pointer_array(&contract, "/required_top_level_keys")? {
        let Some(key) = key.as_str() else {
            return Err("required_top_level_keys entries must be strings".to_string());
        };
        require(
            evidence.get(key).is_some(),
            format!("evidence missing required top-level key {key}"),
        )?;
    }
    Ok(())
}

#[test]
fn context_intelligence_closeout_child_artifact_map_is_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    let required_children = required_set(&contract, "/required_child_bead_ids")?;
    let child_map = pointer_array(&evidence, "/child_artifact_map")?;

    require(
        child_map.len() == required_children.len(),
        "child_artifact_map must have exactly one row per required child",
    )?;

    let mut observed = HashSet::new();
    for row in child_map {
        let bead = pointer_str(row, "/bead_id")?;
        require(
            required_children.contains(bead),
            format!("unexpected child bead mapping {bead}"),
        )?;
        require(
            observed.insert(bead.to_string()),
            format!("duplicate child bead mapping {bead}"),
        )?;
        require(
            pointer_str(row, "/status")? == "closed",
            format!("{bead} must be closed"),
        )?;
        require(
            !pointer_str(row, "/close_reason")?.trim().is_empty(),
            format!("{bead} close_reason must be non-empty"),
        )?;
        require_hex_commit(row, "/commit")?;
        require_non_empty_array(row, "/test_paths", &format!("{bead}.test_paths"))?;
        require_non_empty_array(
            row,
            "/docs_or_evidence_paths",
            &format!("{bead}.docs_or_evidence_paths"),
        )?;
        require_non_empty_array(
            row,
            "/validation_commands",
            &format!("{bead}.validation_commands"),
        )?;
    }

    require(
        observed == required_children,
        "child_artifact_map ids must exactly match required child bead ids",
    )
}

#[test]
fn context_intelligence_closeout_checklist_and_quality_gates_are_complete() -> TestResult {
    let contract = load_json(CONTRACT_PATH)?;
    let evidence = load_json(EVIDENCE_PATH)?;
    let required_checks = required_set(&contract, "/required_check_ids")?;
    let required_quality_gates = required_set(&contract, "/required_quality_gate_ids")?;

    let observed_required_checks = string_set(&evidence, "/required_checks")?;
    require(
        observed_required_checks == required_checks,
        "required_checks must exactly match the contract",
    )?;
    require(
        pointer_array(&evidence, "/missing_checks")?.is_empty(),
        "missing_checks must be empty for a passing gate",
    )?;
    require(
        !pointer_bool(&evidence, "/follow_up_required")?,
        "follow_up_required must be false for a passing gate",
    )?;
    require(
        pointer_array(&evidence, "/follow_up_beads")?.is_empty(),
        "follow_up_beads must be empty for a passing gate",
    )?;

    let mut checklist_ids = HashSet::new();
    for row in pointer_array(&evidence, "/checklist")? {
        let id = pointer_str(row, "/id")?;
        require(
            required_checks.contains(id),
            format!("unexpected checklist id {id}"),
        )?;
        require(
            pointer_str(row, "/status")? == "pass",
            format!("checklist row {id} must pass"),
        )?;
        require_non_empty_array(row, "/evidence", &format!("{id}.evidence"))?;
        checklist_ids.insert(id.to_string());
    }
    require(
        checklist_ids == required_checks,
        "checklist ids must exactly match required checks",
    )?;

    let mut quality_gate_ids = HashSet::new();
    for gate in pointer_array(&evidence, "/quality_gate_results")? {
        let id = pointer_str(gate, "/id")?;
        require(
            required_quality_gates.contains(id),
            format!("unexpected quality gate id {id}"),
        )?;
        require(
            pointer_str(gate, "/status")? == "pass",
            format!("quality gate {id} must pass"),
        )?;
        require(
            !pointer_str(gate, "/command")?.trim().is_empty(),
            format!("quality gate {id} command must be non-empty"),
        )?;
        quality_gate_ids.insert(id.to_string());
    }
    require(
        quality_gate_ids == required_quality_gates,
        "quality gate ids must exactly match required quality gates",
    )
}

#[test]
fn context_intelligence_closeout_redaction_perf_readme_and_push_rows_pass() -> TestResult {
    let evidence = load_json(EVIDENCE_PATH)?;

    for id in [
        "redaction_invalidation",
        "perf_budgets",
        "operator_docs",
        "readme_freshness",
        "pushed_commits",
    ] {
        let row = checklist_row(&evidence, id)?;
        require(
            pointer_str(row, "/status")? == "pass",
            format!("{id} checklist row must pass"),
        )?;
    }

    let pushed = checklist_row(&evidence, "pushed_commits")?;
    let pushed_evidence = pointer_array(pushed, "/evidence")?;
    let snapshot = pushed_evidence
        .first()
        .ok_or_else(|| "pushed_commits evidence must not be empty".to_string())?;
    require_hex_commit(snapshot, "/head")?;
    require_hex_commit(snapshot, "/origin_main")?;
    require_hex_commit(snapshot, "/origin_master")?;
    let child_commits = pointer_array(snapshot, "/child_commits")?;
    require(
        child_commits.len() == 10,
        "pushed snapshot must list 10 child commits",
    )?;
    for (index, commit) in child_commits.iter().enumerate() {
        let Some(commit) = commit.as_str() else {
            return Err(format!("child commit at index {index} must be a string"));
        };
        require(
            is_hex_commit(commit),
            format!("child commit at index {index} must be a 40-character hex hash"),
        )?;
    }

    let quality = checklist_row(&evidence, "quality_gates")?;
    let quality_evidence = pointer_array(quality, "/evidence")?;
    let Some(first) = quality_evidence.first() else {
        return Err("quality_gates evidence must not be empty".to_string());
    };
    require(
        pointer_bool(first, "/heavy_cargo_uses_rch")?,
        "quality gate evidence must prove heavy Cargo gates used RCH",
    )
}
