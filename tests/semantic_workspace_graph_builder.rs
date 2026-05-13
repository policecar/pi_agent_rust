#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Utc};
use pi::semantic_workspace_graph::{
    BeadActionabilityStatus, ContextArtifactCacheScope, ContextArtifactCacheStatus,
    ContextBundleBudget, ContextBundleCacheProbe, ContextBundleRequest, EvidenceFreshnessStatus,
    GraphInputStatus, RedactionStatus, SemanticContextBundlePlanner, SemanticEdgeType,
    SemanticNodeType, SemanticWorkspaceGraph, SemanticWorkspaceGraphBuilder,
    normalize_context_artifact_path,
};
use serde_json::json;
use std::error::Error;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn reference_time() -> TestResult<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339("2026-05-13T00:00:00Z")?.with_timezone(&Utc))
}

fn write_fixture(root: &Path, relative_path: &str, content: &str) -> TestResult {
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn fixture_workspace() -> TestResult<TempDir> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();

    write_fixture(
        root,
        "src/lib.rs",
        r"
pub mod providers;

pub struct Widget;

pub fn build_widget() -> Widget {
    Widget
}
",
    )?;
    write_fixture(
        root,
        "src/providers/openai.rs",
        r"
pub struct OpenAiProvider;

pub fn stream_response() {}
",
    )?;
    write_fixture(
        root,
        "src/session.rs",
        r"
pub struct SessionStore;

pub fn save_session() {}
",
    )?;
    write_fixture(
        root,
        "src/extensions.rs",
        r"
pub struct ExtensionHost;

pub fn load_extension() {}
",
    )?;
    write_fixture(
        root,
        "tests/widget_flow.rs",
        r"
#[test]
fn builds_widget() {
    assert_eq!(2 + 2, 4);
}
",
    )?;
    write_fixture(
        root,
        "tests/provider_streaming.rs",
        r"
#[test]
fn streams_openai_provider() {
    assert_eq!(2 + 2, 4);
}
",
    )?;
    write_fixture(
        root,
        "tests/session_flow.rs",
        r"
#[test]
fn saves_session() {
    assert_eq!(2 + 2, 4);
}
",
    )?;
    write_fixture(
        root,
        "tests/extension_flow.rs",
        r"
#[test]
fn loads_extension() {
    assert_eq!(2 + 2, 4);
}
",
    )?;
    write_fixture(
        root,
        "README.md",
        r"
# Pi Fixture

## Evidence

Strict drop-in certification cites docs/evidence/dropin-certification-verdict.json.
Release-facing claims must suppress docs/evidence/uncertified.json.
Missing evidence must suppress docs/evidence/missing.json.
Perf budget claims cite tests/perf/reports/budget_summary.json.
Extension closeout claims cite docs/evidence/extension-health-delta-failure-disposition.json.
Parity ledger claims cite docs/evidence/dropin-parity-gap-ledger.json.
",
    )?;
    write_fixture(
        root,
        "docs/evidence/dropin-certification-verdict.json",
        r#"{
  "schema": "pi.dropin_certification.verdict.v1",
  "generated_at": "2026-01-01T00:00:00Z",
  "overall_verdict": "CERTIFIED",
  "claim_surface": "release_facing"
}"#,
    )?;
    write_fixture(
        root,
        "tests/perf/reports/budget_summary.json",
        r#"{
  "schema": "pi.perf.budget_summary.v1",
  "generated_at": "2026-05-13T00:00:00Z",
  "claim_surface": "release_facing"
}"#,
    )?;
    write_fixture(
        root,
        "docs/evidence/extension-health-delta-failure-disposition.json",
        r#"{
  "schema": "pi.ext.health_delta_failure_disposition.v1",
  "generated_at": "2026-05-13T00:00:00Z",
  "source_report_generated_at": "2026-05-13T00:00:00Z",
  "claim_surface": "release_facing"
}"#,
    )?;
    write_fixture(
        root,
        "docs/evidence/dropin-parity-gap-ledger.json",
        r#"{
  "schema": "pi.dropin.parity_gap_ledger.v1",
  "generated_at_utc": "2026-05-13T00:00:00Z",
  "claim_surface": "release_facing",
  "gaps": []
}"#,
    )?;
    write_fixture(
        root,
        "docs/evidence/uncertified.json",
        r#"{
  "schema": "pi.dropin_certification.verdict.v1",
  "generated_at": "2026-05-13T00:00:00Z",
  "overall_verdict": "NOT_CERTIFIED",
  "claim_surface": "release_facing"
}"#,
    )?;
    write_fixture(root, "docs/evidence/malformed.json", "{ not valid json")?;
    let issues = [
        json!({
            "id": "bd-open",
            "title": "Open work",
            "status": "open",
            "priority": 1,
            "issue_type": "feature",
            "updated_at": "2026-05-13T00:00:00Z",
            "external_ref": "docs/evidence/dropin-parity-gap-ledger.json"
        })
        .to_string(),
        json!({
            "id": "bd-blocked",
            "title": "Blocked work",
            "status": "open",
            "priority": 1,
            "issue_type": "feature",
            "updated_at": "2026-05-13T00:00:00Z",
            "dependencies": [
                {
                    "issue_id": "bd-blocked",
                    "depends_on_id": "bd-open",
                    "type": "blocks"
                }
            ]
        })
        .to_string(),
        json!({
            "id": "bd-claimed",
            "title": "Claimed work",
            "status": "in_progress",
            "priority": 1,
            "issue_type": "task",
            "updated_at": "2026-05-13T00:00:00Z"
        })
        .to_string(),
        json!({
            "id": "bd-closed",
            "title": "Closed work",
            "status": "closed",
            "priority": 2,
            "issue_type": "task",
            "closed_at": "2026-05-01T00:00:00Z"
        })
        .to_string(),
        json!({
            "id": "bd-tombstone",
            "title": "Deleted work",
            "status": "tombstone",
            "deleted": true
        })
        .to_string(),
        "{ not valid bead json".to_string(),
    ]
    .join("\n");
    write_fixture(root, ".beads/issues.jsonl", &issues)?;

    Ok(temp)
}

fn add_sensitive_context_fixtures(root: &Path) -> TestResult {
    write_fixture(
        root,
        "tests/fixtures/vcr/oauth_refresh_sensitive.json",
        r#"{
  "schema": "pi.vcr.fixture.v1",
  "generated_at": "2026-05-13T00:00:00Z",
  "authorization": "Bearer sk-secret",
  "request": {"body": {"prompt": "hidden prompt"}},
  "response": {"body": {"access_token": "hidden token"}}
}"#,
    )?;
    write_fixture(
        root,
        "tests/fixtures/context_artifacts/provider-auth.log",
        "request body contains API_KEY=sk-secret and prompt text",
    )
}

fn build_fixture_graph(root: &Path) -> TestResult<SemanticWorkspaceGraph> {
    Ok(SemanticWorkspaceGraphBuilder::new(root)
        .with_reference_time(reference_time()?)
        .add_expected_path("docs/evidence/missing.json")
        .build()?)
}

fn node_with_source<'a>(
    graph: &'a SemanticWorkspaceGraph,
    node_type: SemanticNodeType,
    source_path: &str,
) -> TestResult<&'a pi::semantic_workspace_graph::SemanticGraphNode> {
    graph
        .nodes
        .iter()
        .find(|node| node.node_type == node_type && node.source_path == source_path)
        .ok_or_else(|| format!("missing {node_type:?} node for {source_path}").into())
}

fn bead_status(
    graph: &SemanticWorkspaceGraph,
    bead_id: &str,
) -> TestResult<BeadActionabilityStatus> {
    let node = graph
        .nodes
        .iter()
        .find(|node| {
            node.node_type == SemanticNodeType::Bead
                && node.metadata.get("bead_id") == Some(&json!(bead_id))
        })
        .ok_or_else(|| format!("missing bead node for {bead_id}"))?;
    node.bead_actionability_status
        .ok_or_else(|| format!("missing bead actionability for {bead_id}").into())
}

fn bundle_golden_summary(
    bundle: &pi::semantic_workspace_graph::SemanticContextBundle,
) -> serde_json::Value {
    json!({
        "selected": bundle
            .selected_items
            .iter()
            .map(|item| json!({
                "path": &item.source_path,
                "title": &item.title,
                "reason": &item.reason,
            }))
            .collect::<Vec<_>>(),
        "stale_suppressions": bundle
            .stale_evidence_suppressions
            .iter()
            .map(|item| json!({
                "path": &item.source_path,
                "reason": &item.reason,
            }))
            .collect::<Vec<_>>(),
        "commands": &bundle.suggested_validation_commands,
        "budget_excluded": bundle
            .excluded_items
            .iter()
            .filter(|item| item.reason == "budget_exceeded")
            .count(),
    })
}

#[test]
fn context_path_normalization_rejects_escape_and_normalizes_safe_paths() {
    let normalized = normalize_context_artifact_path("./src/../src/session.rs");
    assert!(normalized.accepted);
    assert_eq!(
        normalized.normalized_path.as_deref(),
        Some("src/session.rs")
    );
    assert_eq!(normalized.reason, "normalized");

    let absolute = normalize_context_artifact_path("/etc/passwd");
    assert!(!absolute.accepted);
    assert_eq!(absolute.reason, "absolute_path_rejected");

    let parent_escape = normalize_context_artifact_path("../secrets/auth.json");
    assert!(!parent_escape.accepted);
    assert_eq!(parent_escape.reason, "parent_escape_rejected");

    let nul = normalize_context_artifact_path("docs/evidence/good.json\0bad");
    assert!(!nul.accepted);
    assert_eq!(nul.reason, "nul_byte_rejected");

    let windows_escape = normalize_context_artifact_path("docs\\..\\secrets\\auth.json");
    assert!(!windows_escape.accepted);
    assert_eq!(windows_escape.reason, "backslash_separator_rejected");
}

#[test]
fn graph_cache_validation_enforces_scope_ttl_and_path_policy() -> TestResult {
    let temp = fixture_workspace()?;
    let reference_time = reference_time()?;
    let cache_scope = ContextArtifactCacheScope::new("workspace-a", "main", "session-a");
    let graph = SemanticWorkspaceGraphBuilder::new(temp.path())
        .with_reference_time(reference_time)
        .with_cache_scope(cache_scope.clone())
        .with_cache_ttl_seconds(900)
        .build()?;
    let now_ns = u64::try_from(reference_time.timestamp())? * 1_000_000_000;

    assert_eq!(
        graph.cache_validation_for_path("./src/../src/session.rs", &cache_scope, now_ns),
        ContextArtifactCacheStatus::Valid
    );
    assert_eq!(
        graph.cache_validation_for_path("src/missing.rs", &cache_scope, now_ns),
        ContextArtifactCacheStatus::MissingFingerprint
    );
    assert_eq!(
        graph.cache_validation_for_path("/etc/passwd", &cache_scope, now_ns),
        ContextArtifactCacheStatus::UnsafePath
    );
    assert_eq!(
        graph.cache_validation_for_path(
            "src/session.rs",
            &ContextArtifactCacheScope::new("workspace-b", "main", "session-a"),
            now_ns
        ),
        ContextArtifactCacheStatus::WorkspaceMismatch
    );
    assert_eq!(
        graph.cache_validation_for_path(
            "src/session.rs",
            &ContextArtifactCacheScope::new("workspace-a", "feature", "session-a"),
            now_ns
        ),
        ContextArtifactCacheStatus::BranchMismatch
    );
    assert_eq!(
        graph.cache_validation_for_path(
            "src/session.rs",
            &ContextArtifactCacheScope::new("workspace-a", "main", "session-b"),
            now_ns
        ),
        ContextArtifactCacheStatus::SessionMismatch
    );
    assert_eq!(
        graph.cache_validation_for_path(
            "src/session.rs",
            &cache_scope,
            now_ns + 901 * 1_000_000_000
        ),
        ContextArtifactCacheStatus::Expired
    );

    Ok(())
}

#[test]
fn builder_indexes_workspace_surfaces_and_classifies_fail_closed() -> TestResult {
    let temp = fixture_workspace()?;
    let graph = build_fixture_graph(temp.path())?;
    let graph_again = build_fixture_graph(temp.path())?;

    assert_eq!(
        serde_json::to_value(&graph)?,
        serde_json::to_value(&graph_again)?
    );

    for node_type in [
        SemanticNodeType::CodeSymbol,
        SemanticNodeType::FileRegion,
        SemanticNodeType::TestCase,
        SemanticNodeType::DocSection,
        SemanticNodeType::EvidenceArtifact,
        SemanticNodeType::Bead,
        SemanticNodeType::ProviderSurface,
        SemanticNodeType::ValidationCommand,
    ] {
        assert!(
            !graph.nodes_by_type(node_type).is_empty(),
            "expected at least one {node_type:?} node"
        );
    }

    let stale = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/dropin-certification-verdict.json",
    )?;
    assert_eq!(stale.freshness_status, Some(EvidenceFreshnessStatus::Stale));
    assert_eq!(
        stale.metadata.get("release_claim_allowed"),
        Some(&json!(false))
    );
    assert_eq!(
        stale.metadata.get("claim_gate_status"),
        Some(&json!("blocked_stale"))
    );
    assert_eq!(
        stale.metadata.get("strict_replacement_claim_allowed"),
        Some(&json!(false))
    );

    let uncertified = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/uncertified.json",
    )?;
    assert_eq!(
        uncertified.freshness_status,
        Some(EvidenceFreshnessStatus::Uncertified)
    );
    assert_eq!(
        uncertified.metadata.get("claim_gate_status"),
        Some(&json!("blocked_uncertified"))
    );

    let perf_budget = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "tests/perf/reports/budget_summary.json",
    )?;
    assert_eq!(
        perf_budget.freshness_status,
        Some(EvidenceFreshnessStatus::Current)
    );
    assert_eq!(
        perf_budget.metadata.get("claim_gate_status"),
        Some(&json!("allowed"))
    );

    let extension_closeout = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/extension-health-delta-failure-disposition.json",
    )?;
    assert_eq!(
        extension_closeout.freshness_status,
        Some(EvidenceFreshnessStatus::Current)
    );
    assert_eq!(
        extension_closeout
            .metadata
            .get("source_report_generated_at"),
        Some(&json!("2026-05-13T00:00:00Z"))
    );

    let parity_ledger = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/dropin-parity-gap-ledger.json",
    )?;
    assert_eq!(
        parity_ledger.freshness_status,
        Some(EvidenceFreshnessStatus::Current)
    );
    assert_eq!(
        parity_ledger.metadata.get("generated_at"),
        Some(&json!("2026-05-13T00:00:00Z"))
    );

    let malformed = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/malformed.json",
    )?;
    assert_eq!(
        malformed.freshness_status,
        Some(EvidenceFreshnessStatus::Malformed)
    );

    let missing = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/missing.json",
    )?;
    assert_eq!(
        missing.freshness_status,
        Some(EvidenceFreshnessStatus::Missing)
    );
    assert_eq!(
        graph.evidence_status_for_path("docs/evidence/missing.json"),
        Some(EvidenceFreshnessStatus::Missing)
    );
    assert_eq!(
        graph.release_claim_allowed_for_path("docs/evidence/missing.json"),
        Some(false)
    );
    assert!(
        graph
            .suppressible_claim_evidence()
            .iter()
            .any(|node| { node.source_path == "docs/evidence/missing.json" })
    );

    for cited_path in [
        "docs/evidence/dropin-certification-verdict.json",
        "docs/evidence/uncertified.json",
        "docs/evidence/missing.json",
        "tests/perf/reports/budget_summary.json",
        "docs/evidence/extension-health-delta-failure-disposition.json",
        "docs/evidence/dropin-parity-gap-ledger.json",
    ] {
        let target = node_with_source(&graph, SemanticNodeType::EvidenceArtifact, cited_path)?;
        assert!(
            graph.edges.iter().any(|edge| {
                edge.edge_type == SemanticEdgeType::CitesEvidence
                    && edge.target == target.id
                    && edge.metadata.get("citation_path") == Some(&json!(cited_path))
            }),
            "missing citation edge for {cited_path}"
        );
    }

    assert_eq!(
        bead_status(&graph, "bd-open")?,
        BeadActionabilityStatus::ActionableOpen
    );
    assert_eq!(
        bead_status(&graph, "bd-blocked")?,
        BeadActionabilityStatus::Blocked
    );
    assert_eq!(
        bead_status(&graph, "bd-claimed")?,
        BeadActionabilityStatus::ClaimedInProgress
    );
    assert_eq!(
        bead_status(&graph, "bd-closed")?,
        BeadActionabilityStatus::ClosedReferenceOnly
    );
    assert_eq!(
        bead_status(&graph, "bd-tombstone")?,
        BeadActionabilityStatus::TombstoneReferenceOnly
    );
    assert_eq!(
        bead_status(&graph, "malformed-line-6")?,
        BeadActionabilityStatus::UnknownFailClosed
    );

    let open_bead = graph
        .nodes
        .iter()
        .find(|node| {
            node.node_type == SemanticNodeType::Bead
                && node.metadata.get("bead_id") == Some(&json!("bd-open"))
        })
        .ok_or("missing bd-open bead node")?;
    assert_eq!(
        open_bead.metadata.get("external_ref"),
        Some(&json!("docs/evidence/dropin-parity-gap-ledger.json"))
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.edge_type == SemanticEdgeType::Tracks
            && edge.reason == "bead_external_ref"
            && edge.source == open_bead.id
            && edge.target == parity_ledger.id
            && edge.metadata.get("external_ref")
                == Some(&json!("docs/evidence/dropin-parity-gap-ledger.json"))
    }));

    assert!(graph.trace.iter().any(|event| {
        event.status == GraphInputStatus::Missing
            && event.source_path == "docs/evidence/missing.json"
    }));
    assert!(graph.trace.iter().any(|event| {
        event.status == GraphInputStatus::Malformed
            && event.source_path == "docs/evidence/malformed.json"
    }));
    assert!(graph.trace.iter().any(|event| {
        event.status == GraphInputStatus::Malformed && event.source_path == ".beads/issues.jsonl"
    }));

    let command_nodes = graph.nodes_by_type(SemanticNodeType::ValidationCommand);
    assert!(command_nodes.iter().any(|node| {
        node.metadata.get("command") == Some(&json!("cargo test --test widget_flow builds_widget"))
    }));

    Ok(())
}

#[test]
fn planner_emits_budgeted_golden_bundles_for_core_task_shapes() -> TestResult {
    let temp = fixture_workspace()?;
    let graph = build_fixture_graph(temp.path())?;
    let planner = SemanticContextBundlePlanner::new(&graph);

    let provider = planner.plan(&ContextBundleRequest {
        query: Some("openai provider streaming".to_string()),
        budget: ContextBundleBudget {
            max_items: 3,
            max_bytes: 4096,
        },
        ..ContextBundleRequest::default()
    });
    assert_eq!(
        bundle_golden_summary(&provider),
        json!({
            "selected": [
                {
                    "path": "tests/provider_streaming.rs",
                    "title": "cargo test --test provider_streaming streams_openai_provider",
                    "reason": "query_match"
                },
                {
                    "path": "tests/provider_streaming.rs",
                    "title": "streams_openai_provider",
                    "reason": "query_match"
                },
                {
                    "path": "src/providers/openai.rs",
                    "title": "openai",
                    "reason": "query_match"
                }
            ],
            "stale_suppressions": [],
            "commands": ["cargo test --test provider_streaming streams_openai_provider"],
            "budget_excluded": 5
        })
    );

    let session = planner.plan(&ContextBundleRequest {
        query: Some("session persistence save".to_string()),
        budget: ContextBundleBudget {
            max_items: 3,
            max_bytes: 4096,
        },
        ..ContextBundleRequest::default()
    });
    assert_eq!(
        bundle_golden_summary(&session),
        json!({
            "selected": [
                {
                    "path": "tests/session_flow.rs",
                    "title": "cargo test --test session_flow saves_session",
                    "reason": "query_match"
                },
                {
                    "path": "tests/session_flow.rs",
                    "title": "saves_session",
                    "reason": "query_match"
                },
                {
                    "path": "src/session.rs",
                    "title": "save_session",
                    "reason": "query_match"
                }
            ],
            "stale_suppressions": [],
            "commands": ["cargo test --test session_flow saves_session"],
            "budget_excluded": 3
        })
    );

    let extension = planner.plan(&ContextBundleRequest {
        query: Some("extension closeout health_delta".to_string()),
        budget: ContextBundleBudget {
            max_items: 3,
            max_bytes: 4096,
        },
        ..ContextBundleRequest::default()
    });
    assert_eq!(
        bundle_golden_summary(&extension),
        json!({
            "selected": [
                {
                    "path": "docs/evidence/extension-health-delta-failure-disposition.json",
                    "title": "pi.ext.health_delta_failure_disposition.v1",
                    "reason": "query_match,current_release_claim_evidence"
                },
                {
                    "path": "tests/extension_flow.rs",
                    "title": "cargo test --test extension_flow loads_extension",
                    "reason": "query_match"
                },
                {
                    "path": "tests/extension_flow.rs",
                    "title": "loads_extension",
                    "reason": "query_match"
                }
            ],
            "stale_suppressions": [],
            "commands": ["cargo test --test extension_flow loads_extension"],
            "budget_excluded": 6
        })
    );

    let swarm = planner.plan(&ContextBundleRequest {
        query: Some("drop-in swarm claim readiness".to_string()),
        bead_id: Some("bd-open".to_string()),
        changed_paths: vec!["README.md".to_string()],
        budget: ContextBundleBudget {
            max_items: 4,
            max_bytes: 2048,
        },
        ..ContextBundleRequest::default()
    });
    let swarm_summary = bundle_golden_summary(&swarm);
    assert_eq!(
        swarm_summary["stale_suppressions"],
        json!([
            {
                "path": "docs/evidence/dropin-certification-verdict.json",
                "reason": "suppressed_stale_or_unsafe_evidence"
            },
            {
                "path": "docs/evidence/uncertified.json",
                "reason": "suppressed_stale_or_unsafe_evidence"
            },
            {
                "path": "docs/evidence/missing.json",
                "reason": "suppressed_stale_or_unsafe_evidence"
            }
        ])
    );
    assert!(swarm.selected_items.iter().any(|item| {
        item.source_path == "docs/evidence/dropin-parity-gap-ledger.json"
            && item.reason.contains("related_to_bead_or_changed_path")
    }));
    assert!(
        swarm
            .excluded_items
            .iter()
            .any(|item| { item.reason == "budget_exceeded" })
    );

    let failing_command = planner.plan(&ContextBundleRequest {
        failing_command: Some("cargo test --test session_flow saves_session".to_string()),
        budget: ContextBundleBudget {
            max_items: 1,
            max_bytes: 512,
        },
        ..ContextBundleRequest::default()
    });
    assert_eq!(
        failing_command.suggested_validation_commands,
        vec!["cargo test --test session_flow saves_session"]
    );

    Ok(())
}

#[test]
fn planner_redacts_sensitive_artifacts_and_fails_closed_cache_validation() -> TestResult {
    let temp = fixture_workspace()?;
    add_sensitive_context_fixtures(temp.path())?;
    let graph = build_fixture_graph(temp.path())?;

    let vcr_node = graph
        .evidence_node_for_path("tests/fixtures/vcr/oauth_refresh_sensitive.json")
        .ok_or("missing sensitive vcr node")?;
    assert_eq!(vcr_node.redaction_status, RedactionStatus::UnsafeToEmit);
    assert_eq!(
        vcr_node
            .metadata
            .get("sensitive_path_kind")
            .and_then(serde_json::Value::as_str),
        Some("vcr_fixture")
    );
    let redacted_keys = vcr_node
        .metadata
        .get("redacted_metadata_keys")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing redacted metadata keys")?;
    assert!(
        redacted_keys
            .iter()
            .any(|key| matches!(key.as_str(), Some("credential_like")))
    );
    assert!(
        redacted_keys
            .iter()
            .any(|key| matches!(key.as_str(), Some("prompt_or_payload")))
    );
    assert!(
        !format!("{:?}", vcr_node.metadata).contains("sk-secret"),
        "graph metadata must not retain raw secret values"
    );

    let log_node = graph
        .evidence_node_for_path("tests/fixtures/context_artifacts/provider-auth.log")
        .ok_or("missing sensitive log node")?;
    assert_eq!(log_node.redaction_status, RedactionStatus::UnsafeToEmit);
    assert_eq!(
        log_node
            .metadata
            .get("sensitive_path_kind")
            .and_then(serde_json::Value::as_str),
        Some("log_artifact")
    );

    let planner = SemanticContextBundlePlanner::new(&graph);
    let bundle = planner.plan(&ContextBundleRequest {
        query: Some("oauth vcr authorization token".to_string()),
        changed_paths: vec![
            "tests/fixtures/vcr/oauth_refresh_sensitive.json".to_string(),
            "../outside/auth.json".to_string(),
        ],
        workspace_id: Some("workspace-a".to_string()),
        branch: Some("main".to_string()),
        session_id: Some("session-a".to_string()),
        generated_at_utc: Some("2026-05-13T00:00:00Z".to_string()),
        cache_ttl_seconds: 900,
        budget: ContextBundleBudget {
            max_items: 6,
            max_bytes: 4096,
        },
        ..ContextBundleRequest::default()
    });

    assert!(
        bundle
            .selected_items
            .iter()
            .all(|item| { item.redaction_status != RedactionStatus::UnsafeToEmit })
    );
    assert!(bundle.excluded_items.iter().any(|item| {
        item.source_path == "tests/fixtures/vcr/oauth_refresh_sensitive.json"
            && item.reason.contains("unsafe_to_emit_by_redaction_policy")
            && item.reason.contains("sensitive_path:vcr_fixture")
    }));
    assert_eq!(
        bundle.redaction_summary.overall_status,
        RedactionStatus::UnsafeToEmit
    );
    assert!(bundle.redaction_summary.suppressed_unsafe_nodes >= 1);
    assert!(
        bundle
            .redaction_summary
            .sensitive_path_kinds
            .contains("vcr_fixture")
    );
    assert!(
        bundle
            .path_normalization
            .iter()
            .any(|path| { !path.accepted && path.reason == "parent_escape_rejected" })
    );

    let valid_probe = ContextBundleCacheProbe {
        workspace_id: "workspace-a".to_string(),
        branch: Some("main".to_string()),
        session_id: Some("session-a".to_string()),
        input_fingerprint_sha256: bundle.invalidation_policy.input_fingerprint_sha256.clone(),
        now_utc: Some("2026-05-13T00:05:00Z".to_string()),
    };
    assert!(
        bundle
            .invalidation_policy
            .validate_probe(&valid_probe)
            .valid
    );

    let expired_probe = ContextBundleCacheProbe {
        workspace_id: "workspace-a".to_string(),
        branch: Some("feature".to_string()),
        session_id: Some("session-a".to_string()),
        input_fingerprint_sha256: "changed".to_string(),
        now_utc: Some("2026-05-13T00:20:00Z".to_string()),
    };
    let expired = bundle.invalidation_policy.validate_probe(&expired_probe);
    assert!(!expired.valid);
    assert!(
        expired
            .invalidation_reasons
            .contains(&"branch_changed".to_string())
    );
    assert!(
        expired
            .invalidation_reasons
            .contains(&"input_fingerprint_changed".to_string())
    );
    assert!(
        expired
            .invalidation_reasons
            .contains(&"cache_ttl_expired".to_string())
    );

    Ok(())
}

#[test]
fn content_hashes_invalidate_without_changing_path_stable_ids() -> TestResult {
    let temp = fixture_workspace()?;
    let before = build_fixture_graph(temp.path())?;
    let before_fingerprint = before
        .input_fingerprints
        .iter()
        .find(|fingerprint| fingerprint.source_path == "src/lib.rs")
        .ok_or("missing src/lib.rs fingerprint before edit")?;
    let before_file_node = node_with_source(&before, SemanticNodeType::FileRegion, "src/lib.rs")?;

    write_fixture(
        temp.path(),
        "src/lib.rs",
        r"
pub mod providers;

pub struct Widget;

pub fn build_widget() -> Widget {
    Widget
}

pub fn build_second_widget() -> Widget {
    Widget
}
",
    )?;

    let after = build_fixture_graph(temp.path())?;
    let after_fingerprint = after
        .input_fingerprints
        .iter()
        .find(|fingerprint| fingerprint.source_path == "src/lib.rs")
        .ok_or("missing src/lib.rs fingerprint after edit")?;
    let after_file_node = node_with_source(&after, SemanticNodeType::FileRegion, "src/lib.rs")?;

    assert_ne!(before_fingerprint.sha256, after_fingerprint.sha256);
    assert_eq!(before_file_node.id, after_file_node.id);
    assert!(after.nodes.iter().any(|node| {
        node.node_type == SemanticNodeType::CodeSymbol && node.title == "build_second_widget"
    }));

    Ok(())
}

#[test]
fn malformed_fixture_classifications_do_not_emit_raw_secret_words() -> TestResult {
    let temp = tempfile::tempdir()?;
    write_fixture(
        temp.path(),
        "docs/evidence/bad.json",
        "{ token: secret authorization",
    )?;

    let graph = SemanticWorkspaceGraphBuilder::new(temp.path()).build()?;
    let encoded = serde_json::to_value(&graph)?;
    let text = serde_json::to_string(&encoded)?;

    assert!(!text.contains("authorization"));
    assert!(!text.contains("token"));
    assert!(!text.contains("secret"));

    let bad = node_with_source(
        &graph,
        SemanticNodeType::EvidenceArtifact,
        "docs/evidence/bad.json",
    )?;
    assert_eq!(
        bad.freshness_status,
        Some(EvidenceFreshnessStatus::Malformed)
    );

    Ok(())
}
