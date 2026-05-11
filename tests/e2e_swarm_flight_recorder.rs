#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]

//! E2E: deterministic swarm flight-recorder replay harness.
//!
//! This test runs real `AgentSession` instances with real session persistence,
//! the built-in read tool, and JS extension lifecycle hooks. Providers are
//! deterministic in-process providers, so the replay path never needs live API
//! credentials.

mod common;

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use async_trait::async_trait;
use futures::Stream;
use pi::agent::{Agent, AgentConfig, AgentEvent, AgentSession, InputSource};
use pi::compaction::ResolvedCompactionSettings;
use pi::error::{Error, Result};
use pi::model::{
    AssistantMessage, ContentBlock, Message, StopReason, StreamEvent, TextContent,
    ToolResultMessage, Usage,
};
use pi::provider::{Context, Provider, StreamOptions};
use pi::session::Session;
use pi::swarm_flight_recorder::{
    SWARM_FLIGHT_RECORDER_EVENT_SCHEMA, SWARM_FLIGHT_RECORDER_REPORT_SCHEMA, SwarmFlightRecorder,
    validate_swarm_flight_recorder_jsonl,
};
use pi::tools::ToolRegistry;
use serde_json::{Value, json};

const EXTENSION_SOURCE: &str = r#"
export default function init(pi) {
  const events = [];
  function remember(name, event) {
    events.push({
      name,
      toolName: event && event.toolName ? event.toolName : null,
      sessionId: event && event.sessionId ? event.sessionId : null,
    });
  }
  pi.on("agent_start", (event) => {
    remember("agent_start", event);
    return null;
  });
  pi.on("turn_start", (event) => {
    remember("turn_start", event);
    return null;
  });
  pi.on("tool_call", (event) => {
    remember("tool_call", event);
    return { block: false };
  });
  pi.on("tool_result", (event) => {
    remember("tool_result", event);
    return null;
  });
  pi.on("agent_end", (event) => {
    remember("agent_end", event);
    return null;
  });
  pi.registerCommand("flight-events", {
    description: "Return hook events captured for the flight recorder",
    handler: async () => JSON.stringify(events),
  });
}
"#;

#[derive(Debug)]
struct FlightProvider {
    read_path: String,
    expected_fragment: String,
    final_text: String,
    stream_calls: AtomicUsize,
}

impl FlightProvider {
    const fn new(read_path: String, expected_fragment: String, final_text: String) -> Self {
        Self {
            read_path,
            expected_fragment,
            final_text,
            stream_calls: AtomicUsize::new(0),
        }
    }

    fn assistant_message(
        &self,
        stop_reason: StopReason,
        content: Vec<ContentBlock>,
    ) -> AssistantMessage {
        AssistantMessage {
            content,
            api: self.api().to_string(),
            provider: self.name().to_string(),
            model: self.model_id().to_string(),
            usage: Usage {
                total_tokens: 12,
                output: 12,
                ..Usage::default()
            },
            stop_reason,
            error_message: None,
            timestamp: 0,
        }
    }

    fn stream_done(
        &self,
        message: AssistantMessage,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>> {
        let partial = self.assistant_message(StopReason::Stop, Vec::new());
        Box::pin(futures::stream::iter(vec![
            Ok(StreamEvent::Start { partial }),
            Ok(StreamEvent::Done {
                reason: message.stop_reason,
                message,
            }),
        ]))
    }

    fn latest_tool_result<'a>(
        context: &'a Context<'a>,
        tool_call_id: &str,
    ) -> Option<&'a ToolResultMessage> {
        context
            .messages
            .iter()
            .rev()
            .filter_map(|message| match message {
                Message::ToolResult(result) => Some(result.as_ref()),
                _ => None,
            })
            .find(|result| result.tool_call_id == tool_call_id)
    }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Provider for FlightProvider {
    fn name(&self) -> &str {
        "flight-recorder-provider"
    }

    fn api(&self) -> &str {
        "flight-recorder-api"
    }

    fn model_id(&self) -> &str {
        "flight-recorder-model"
    }

    async fn stream(
        &self,
        context: &Context<'_>,
        _options: &StreamOptions,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>>> {
        let call_index = self.stream_calls.fetch_add(1, Ordering::SeqCst);
        if call_index == 0 {
            return Ok(self.stream_done(self.assistant_message(
                StopReason::ToolUse,
                vec![ContentBlock::ToolCall(pi::model::ToolCall {
                    id: "flight-read-1".to_string(),
                    name: "read".to_string(),
                    arguments: json!({ "path": self.read_path }),
                    thought_signature: None,
                })],
            )));
        }

        if call_index == 1 {
            let Some(result) = Self::latest_tool_result(context, "flight-read-1") else {
                return Err(Error::api("flight provider expected read tool result"));
            };
            let text = result
                .content
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Text(text) => Some(text.text.as_str()),
                    _ => None,
                })
                .collect::<String>();
            if !text.contains(&self.expected_fragment) {
                return Err(Error::api(
                    "flight provider read result missed expected fragment",
                ));
            }
            return Ok(self.stream_done(self.assistant_message(
                StopReason::Stop,
                vec![ContentBlock::Text(TextContent::new(
                    self.final_text.clone(),
                ))],
            )));
        }

        Err(Error::api(
            "flight provider received unexpected stream call",
        ))
    }
}

#[derive(Debug)]
struct FlightSessionEvidence {
    agent_name: String,
    final_text: String,
    session_entries: usize,
    extension_events: Vec<String>,
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn elapsed_start() -> Instant {
    Instant::now()
}

async fn run_flight_session(
    agent_name: String,
    input_source: InputSource,
    workspace: std::path::PathBuf,
    recorder: Arc<StdMutex<SwarmFlightRecorder>>,
) -> Result<FlightSessionEvidence> {
    std::fs::create_dir_all(workspace.join("extensions"))?;
    std::fs::create_dir_all(workspace.join("fixtures"))?;
    let fixture_path = workspace.join("fixtures/input.txt");
    std::fs::write(
        &fixture_path,
        format!("agent={agent_name}\nflight_recorder=enabled\n"),
    )?;
    let extension_path = workspace.join("extensions/flight.mjs");
    std::fs::write(&extension_path, EXTENSION_SOURCE)?;

    let provider: Arc<dyn Provider> = Arc::new(FlightProvider::new(
        fixture_path.display().to_string(),
        "flight_recorder=enabled".to_string(),
        format!("{agent_name} flight complete"),
    ));
    let tools = ToolRegistry::new(&["read"], &workspace, None);
    let config = AgentConfig {
        system_prompt: None,
        max_tool_iterations: 4,
        stream_options: StreamOptions {
            api_key: Some("offline-flight-recorder-key".to_string()),
            session_id: Some(agent_name.clone()),
            ..StreamOptions::default()
        },
        block_images: false,
        fail_closed_hooks: true,
    };
    let agent = Agent::new(provider, tools, config);
    let session = Arc::new(asupersync::sync::Mutex::new(Session::create_with_dir(
        Some(workspace.join("sessions")),
    )));
    let mut agent_session = AgentSession::new(
        agent,
        Arc::clone(&session),
        true,
        ResolvedCompactionSettings::default(),
    );
    agent_session.set_input_source(input_source);
    agent_session
        .enable_extensions(&[], &workspace, None, &[extension_path])
        .await?;

    let started_at = elapsed_start();
    let event_recorder = Arc::clone(&recorder);
    let event_agent = agent_name.clone();
    let message = agent_session
        .run_text(
            format!("Inspect the flight fixture for {agent_name}."),
            move |event: AgentEvent| {
                event_recorder
                    .lock()
                    .expect("lock flight recorder")
                    .record_agent_event(event_agent.clone(), elapsed_ms(started_at), &event)
                    .expect("record agent event");
            },
        )
        .await?;

    let extension_value = agent_session
        .execute_extension_command("flight-events", "", 5_000, |_| {})
        .await?;
    let extension_events = extension_value
        .as_str()
        .and_then(|value| serde_json::from_str::<Vec<Value>>(value).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| {
            value
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();

    let session_entries = {
        let cx = pi::agent_cx::AgentCx::for_current_or_request();
        let guard = session.lock(cx.cx()).await?;
        guard.entries_for_current_path().len()
    };

    recorder
        .lock()
        .expect("lock flight recorder")
        .record_session_snapshot(
            agent_name.clone(),
            agent_name.clone(),
            elapsed_ms(started_at),
            json!({
                "session_dir": workspace.join("sessions").display().to_string(),
                "entry_count": session_entries,
                "input_source": input_source.as_str(),
            }),
        )?;
    recorder
        .lock()
        .expect("lock flight recorder")
        .record_extension_event(
            agent_name.clone(),
            agent_name.clone(),
            elapsed_ms(started_at),
            json!({
                "hook_events": extension_events,
                "extension_entry": workspace.join("extensions/flight.mjs").display().to_string(),
            }),
        )?;

    let final_text = message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<String>();

    Ok(FlightSessionEvidence {
        agent_name,
        final_text,
        session_entries,
        extension_events,
    })
}

#[test]
fn multi_agent_flight_recorder_bundle_replays_without_credentials() {
    let test_name = "multi_agent_flight_recorder_bundle_replays_without_credentials";
    let harness = common::TestHarness::new(test_name);
    let recorder = Arc::new(StdMutex::new(
        SwarmFlightRecorder::new("flight-recorder-e2e").expect("create recorder"),
    ));

    let alpha_workspace = harness.temp_path("agents/alpha");
    let beta_workspace = harness.temp_path("agents/beta");
    let (alpha, beta) = common::run_async({
        let recorder_a = Arc::clone(&recorder);
        let recorder_b = Arc::clone(&recorder);
        async move {
            futures::future::join(
                run_flight_session(
                    "agent-alpha".to_string(),
                    InputSource::Rpc,
                    alpha_workspace,
                    recorder_a,
                ),
                run_flight_session(
                    "agent-beta".to_string(),
                    InputSource::Interactive,
                    beta_workspace,
                    recorder_b,
                ),
            )
            .await
        }
    });
    let alpha = alpha.expect("alpha session succeeds");
    let beta = beta.expect("beta session succeeds");

    assert_eq!(alpha.agent_name, "agent-alpha");
    assert_eq!(beta.agent_name, "agent-beta");
    assert!(alpha.final_text.contains("agent-alpha flight complete"));
    assert!(beta.final_text.contains("agent-beta flight complete"));
    assert!(
        alpha.session_entries >= 4,
        "alpha session should persist entries"
    );
    assert!(
        beta.session_entries >= 4,
        "beta session should persist entries"
    );
    assert!(
        alpha
            .extension_events
            .iter()
            .any(|event| matches!(event.as_str(), "tool_call")),
        "alpha extension should observe tool_call: {:?}",
        alpha.extension_events
    );
    assert!(
        beta.extension_events
            .iter()
            .any(|event| matches!(event.as_str(), "tool_result")),
        "beta extension should observe tool_result: {:?}",
        beta.extension_events
    );

    recorder
        .lock()
        .expect("lock recorder")
        .record_coordination_marker(
            "GoldenGlacier",
            0,
            "agent_mail_degraded_beads_fallback",
            json!({
                "status": "red",
                "mode": "beads_soft_lock_fallback",
                "summary": "Agent Mail unavailable; Beads used as non-blocking soft lock",
                "token": "must-redact",
            }),
        )
        .expect("record coordination marker");

    let bundle_path = harness.temp_path("swarm_flight_recorder.jsonl");
    let report_path = harness.temp_path("swarm_flight_recorder_report.json");
    let jsonl = recorder
        .lock()
        .expect("lock recorder")
        .to_jsonl()
        .expect("jsonl");
    std::fs::write(&bundle_path, &jsonl).expect("write flight recorder bundle");
    let rows = validate_swarm_flight_recorder_jsonl(&jsonl).expect("valid flight jsonl");
    assert_eq!(rows[0].schema, SWARM_FLIGHT_RECORDER_EVENT_SCHEMA);
    assert!(
        rows.iter().any(|row| row
            .redaction
            .redacted_keys
            .iter()
            .any(|key| matches!(key.as_str(), "token"))),
        "coordination token should be redacted in bundle"
    );
    assert!(
        rows.iter()
            .any(|row| matches!(row.component.as_str(), "agent")
                && matches!(row.event_kind.as_str(), "tool_execution_start")),
        "bundle should contain tool timing events"
    );
    assert!(
        rows.iter()
            .any(|row| matches!(row.component.as_str(), "session")),
        "bundle should contain session snapshots"
    );
    assert!(
        rows.iter()
            .any(|row| matches!(row.component.as_str(), "extension")),
        "bundle should contain extension hook summaries"
    );

    let report = recorder.lock().expect("lock recorder").build_report(
        "cargo test --test e2e_swarm_flight_recorder -- --exact multi_agent_flight_recorder_bundle_replays_without_credentials --nocapture",
        vec![bundle_path.display().to_string()],
    );
    assert_eq!(report.schema, SWARM_FLIGHT_RECORDER_REPORT_SCHEMA);
    assert_eq!(report.agent_count, 3);
    assert!(!report.replay.requires_live_provider_credentials);
    assert!(
        report
            .dominant_latency_components
            .iter()
            .any(|entry| matches!(entry.component.as_str(), "localTools")),
        "report should attribute tool latency: {:?}",
        report.dominant_latency_components
    );
    assert_eq!(report.coordination_failures.len(), 1);
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).expect("serialize report"),
    )
    .expect("write report");
    harness.record_artifact("swarm_flight_recorder.jsonl", &bundle_path);
    harness.record_artifact("swarm_flight_recorder_report.json", &report_path);

    harness
        .write_jsonl_logs(harness.temp_path("swarm_flight_recorder_test.log.jsonl"))
        .expect("write test log");
}
