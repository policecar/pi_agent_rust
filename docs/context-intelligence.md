# Context Intelligence

Context intelligence is Pi's advisory semantic workspace graph and bundle
planner. It indexes code, tests, docs, evidence, Beads, provider surfaces, and
validation commands so an agent turn can receive focused navigation context. It
does not replace Beads for work state, Agent Mail for coordination, Doctor or
runpacks for operator posture, RCH for validation, README freshness checks, or
drop-in certification gates.

## Configuration

The shipped user-facing entry point is `pi context-preview`. It is read-only:
the command performs no provider calls, no writes, no Beads mutations, and no
Agent Mail reservations.

```bash
pi context-preview \
  --format text \
  --bead bd-ircr3.11 \
  --changed-path scripts/build_swarm_operator_runpack.py \
  --failing-command "rch exec -- cargo test --test semantic_workspace_graph_builder context" \
  --max-items 24 \
  --max-bytes 32768 \
  context intelligence closeout docs gate
```

The relevant bundle knobs are:

- `--format text|json`: text is for operators, JSON is for machine evidence.
- `--bead`: task anchor used to score Beads and adjacent artifacts.
- `--changed-path`: repeatable path anchor for files under active edit.
- `--failing-command`: validation command anchor for test and command nodes.
- `--max-items` and `--max-bytes`: hard bundle limits.
- trailing query text: free-form task intent used for relevance scoring.

AgentSession prompt injection is opt-in through `SemanticContextBundleInjection`
inside Rust code. The CLI preview does not automatically attach a bundle to a
live provider turn.

## Preview Workflow

1. Run `pi context-preview --format text ...` with at least one signal: query,
   `--bead`, `--changed-path`, or `--failing-command`.
2. Inspect selected items, excluded items, stale evidence suppressions,
   suggested validation commands, redaction status, and cache TTL.
3. Use selected paths as navigation hints only. Read authoritative source files
   directly before editing.
4. Run the suggested validation commands with RCH when they compile Rust.
5. Capture JSON when evidence is needed:

```bash
pi context-preview --format json \
  --bead bd-ircr3.11 \
  --changed-path docs/context-intelligence.md \
  --changed-path scripts/build_swarm_operator_runpack.py \
  context intelligence operator docs final gate
```

## Failure Modes

Context intelligence fails closed. Missing, unreadable, malformed, stale,
historical, uncertified, or freshness-unknown evidence is classified instead of
being silently promoted to current context. Closed and tombstoned Beads can be
reference nodes, but they are never actionable work.

Common degraded reasons:

- `semantic_graph_missing_inputs`: an expected source path is absent.
- `semantic_graph_malformed_inputs`: JSON or structured evidence could not be
  parsed.
- `context_bundle_empty`: no candidate survived scoring and policy filters.
- `context_bundle_partial_coverage`: the selected bundle lacks enough linked
  tests or validation commands.
- `stale_or_unsafe_evidence_suppressed`: stale or unsafe evidence was omitted.
- `selected_code_without_test_link`: code context was selected without a linked
  test signal.
- `context_cache_pressure`: cache fingerprints are not reusable under the
  current workspace, branch, session, or TTL.

## Privacy Posture

The graph stores metadata and redacted summaries, not raw prompts or provider
payloads. Sensitive keys and path classes are suppressed or redacted, including
API keys, tokens, cookies, authorization headers, raw user prompts, raw model
responses, Agent Mail registration tokens, VCR HTTP bodies, and session
transcripts.

The prompt renderer repeats that stale, uncertified, or unsafe evidence is not
current release evidence. If redaction status reaches `unsafe_to_emit`, the
bundle excludes that item rather than exposing it to a provider.

## Examples

Investigate a failing context planner test:

```bash
pi context-preview --format text \
  --failing-command "rch exec -- cargo test --test semantic_workspace_graph_builder context" \
  --changed-path src/semantic_workspace_graph.rs \
  semantic bundle planner deterministic replay
```

Prepare a closeout review for this program:

```bash
pi context-preview --format json \
  --bead bd-ircr3.11 \
  --changed-path docs/context-intelligence.md \
  --changed-path docs/contracts/context-intelligence-closeout-gate-contract.json \
  --changed-path scripts/build_swarm_operator_runpack.py \
  context intelligence closeout final gate child artifact map
```

Inspect swarm posture through Doctor:

```bash
pi doctor --only swarm --format json
```

The Doctor output includes `pi.doctor.context_intelligence_posture.v1` when the
graph can be built from the current workspace. The swarm runpack projects that
same posture under `doctor_swarm.context_intelligence`.

## Troubleshooting

- If the preview says no context signals were supplied, add query text,
  `--bead`, `--changed-path`, or `--failing-command`.
- If relevant code is missing, rerun from the repository root and include a
  more specific changed path.
- If evidence is suppressed as stale or uncertified, refresh the source evidence
  or treat it as historical context only.
- If redaction suppresses an artifact, inspect the source locally and avoid
  provider-bound bundle use until the artifact can be summarized safely.
- If cache pressure appears, rebuild the preview after the branch, workspace,
  or session identity settles.
- If Agent Mail is degraded, keep using Beads as the work-state source of truth;
  context intelligence does not infer reservations.

## Closeout Gate

The final program closeout gate emits
`pi.context_intelligence.closeout_gate.v1`, governed by
`docs/contracts/context-intelligence-closeout-gate-contract.json`. The gate maps
each child bead from `bd-ircr3.1` through `bd-ircr3.10` to code paths, tests,
docs or evidence paths, validation commands, close reasons, and commit hashes.
It also checks operator docs, README freshness, staged UBS, bead ledger
reconciliation, focused RCH tests, broad RCH cargo gates, and pushed
`origin/main` plus `origin/master` state.

```bash
python3 scripts/build_swarm_operator_runpack.py \
  --run-context-intelligence-final-gate \
  --out-context-intelligence-final-gate-json docs/evidence/context-intelligence-closeout-gate.json \
  --quality-gate-result "py_compile=pass:python3 -m py_compile scripts/build_swarm_operator_runpack.py" \
  --quality-gate-result "runpack_self_test=pass:python3 scripts/build_swarm_operator_runpack.py --self-test" \
  --quality-gate-result "json_contracts=pass:python3 -m json.tool docs/contracts/context-intelligence-closeout-gate-contract.json" \
  --quality-gate-result "semantic_context_graph_contract_rch=pass:rch exec -- cargo test --test semantic_context_graph_contract -- --nocapture" \
  --quality-gate-result "semantic_workspace_graph_contract_rch=pass:rch exec -- cargo test --test semantic_workspace_graph_contract -- --nocapture" \
  --quality-gate-result "semantic_workspace_graph_builder_rch=pass:rch exec -- cargo test --test semantic_workspace_graph_builder context" \
  --quality-gate-result "context_intelligence_e2e_rch=pass:rch exec -- cargo test --test e2e_agent_loop context_intelligence_no_mock_harness -- --nocapture" \
  --quality-gate-result "doctor_context_intelligence_rch=pass:rch exec -- cargo test --test doctor_swarm_temp_dir_json context_intelligence -- --nocapture" \
  --quality-gate-result "context_perf_budgets_rch=pass:rch exec -- cargo test --test perf_budgets context_intelligence" \
  --quality-gate-result "context_intelligence_closeout_gate_contract_rch=pass:rch exec -- cargo test --test context_intelligence_closeout_gate_contract -- --nocapture" \
  --quality-gate-result "cargo_fmt=pass:cargo fmt --check" \
  --quality-gate-result "cargo_check_all_targets_rch=pass:CARGO_TARGET_DIR=$CARGO_TARGET_DIR TMPDIR=$TMPDIR rch exec -- cargo check --all-targets" \
  --quality-gate-result "cargo_clippy_all_targets_rch=pass:CARGO_TARGET_DIR=$CARGO_TARGET_DIR TMPDIR=$TMPDIR rch exec -- cargo clippy --all-targets -- -D warnings" \
  --quality-gate-result "staged_ubs=pass:timeout 60s ubs --staged --only=rust ." \
  --quality-gate-result "beads_ledger_reconcile=pass:./scripts/reconcile_beads_ledger.sh"
```

A failing gate emits `follow_up_beads` and
`decision=file_follow_up_beads_before_closing_epic`. A passing gate is closeout
evidence only; it is not a new source of truth.
