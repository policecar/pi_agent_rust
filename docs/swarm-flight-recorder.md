# Swarm Flight Recorder

The swarm flight recorder is a deterministic E2E evidence harness for multi-agent runs. It records redacted runtime events from real `AgentSession` execution, built-in tool calls, JS extension hooks, session persistence snapshots, and external coordination markers into JSONL rows with schema `pi.swarm.flight_recorder.event.v1`.

The harness is designed for replay without live provider credentials. Tests use deterministic in-process providers and real Pi runtime components, so operators can inspect timing and coordination behavior without depending on OpenAI, Anthropic, or other provider accounts.

## Artifacts

- `swarm_flight_recorder.jsonl`: append-only event rows with `correlationId`, `agentName`, `component`, `eventKind`, redaction summary, and redacted payload.
- `swarm_flight_recorder_report.json`: summary report with schema `pi.swarm.flight_recorder.report.v1`, replay command, dominant latency components, component counts, and coordination failures.

Every JSONL row is validated by `validate_swarm_flight_recorder_jsonl` for current schema, monotonic sequence numbers, and required identity fields. Sensitive payload keys such as tokens, prompts, API keys, cookies, secrets, transcripts, and message content are replaced with `[REDACTED]`, and the row records which keys were redacted.

## Replay

Run the focused deterministic replay with:

```bash
rch exec -- cargo test --test e2e_swarm_flight_recorder -- --exact multi_agent_flight_recorder_bundle_replays_without_credentials --nocapture
```

The report embeds the same cargo test command without the `rch exec --` prefix so local artifact readers can see the underlying replay target. Agents must still use `rch exec --` for CPU-heavy validation in this repository.

## What The Harness Proves

- Multiple Pi sessions can run against isolated temp workspaces in one scenario.
- Built-in tool execution is real, not a synthetic fixture.
- Session persistence is exercised through real `Session` state.
- JS extension lifecycle hooks observe agent, turn, tool call, and tool result activity.
- Agent Mail or other coordination failures can be captured as non-blocking markers while Beads remains the soft-lock fallback.
- The summary report identifies the dominant measured latency contributors and coordination failures from the event bundle.
