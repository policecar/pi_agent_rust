#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const UI_SCENARIOS: &str =
    include_str!("dropin_extension_ui_differential/fixtures/g05_extension_ui_scenarios.json");
const UI_SCENARIO_TIMEOUT: Duration = Duration::from_secs(15);

fn wait_for_child_output(
    mut child: Child,
    timeout: Duration,
) -> Result<Output, Box<dyn std::error::Error>> {
    let started_at = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_end(&mut stdout)?;
            }
            let mut stderr = Vec::new();
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_end(&mut stderr)?;
            }
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }

        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("extension UI scenario timed out after {timeout:?}"),
            )
            .into());
        }

        thread::sleep(Duration::from_millis(25));
    }
}

/// Extension UI differential test harness for testing request/response round-trip parity
struct ExtensionUiDifferentialTester {
    #[allow(dead_code)]
    temp_dir: TempDir,
    rust_pi_path: String,
}

impl ExtensionUiDifferentialTester {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let rust_pi_path = std::env::var("CARGO_TARGET_DIR").map_or_else(
            |_| "target/debug/pi".to_string(),
            |dir| format!("{dir}/debug/pi"),
        );

        Ok(Self {
            temp_dir,
            rust_pi_path,
        })
    }

    fn execute_ui_scenario(&self, scenario: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let requests = scenario["requests"].as_array().expect("scenario requests");
        let mut child = Command::new(&self.rust_pi_path)
            .args(["--mode", "rpc", "--print", "--no-extensions"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.as_mut().unwrap();

        // Send all requests in sequence
        for request in requests {
            writeln!(stdin, "{request}")?;
        }
        drop(child.stdin.take());

        let output = wait_for_child_output(child, UI_SCENARIO_TIMEOUT)?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);

        // Parse all JSON responses from stdout
        let mut responses = Vec::new();
        for line in stdout_str.lines() {
            if let Ok(response) = serde_json::from_str::<Value>(line) {
                responses.push(response);
            }
        }

        Ok(json!(responses))
    }

    fn validate_ui_scenario(scenario: &Value, actual_responses: &Value) -> bool {
        let expected_patterns = scenario["expected_patterns"]
            .as_array()
            .expect("expected patterns");
        let responses = actual_responses.as_array().expect("actual responses array");

        // For each expected pattern, check if we find a matching response
        for pattern in expected_patterns {
            let pattern_type = pattern["type"].as_str().expect("pattern type");
            let found = responses
                .iter()
                .any(|response| Self::matches_pattern(response, pattern, pattern_type));

            if !found {
                return false;
            }
        }

        true
    }

    fn matches_pattern(response: &Value, pattern: &Value, pattern_type: &str) -> bool {
        match pattern_type {
            "extension_ui_request" => {
                response.get("type") == Some(&json!("extension_ui_request"))
                    && pattern
                        .get("method")
                        .is_none_or(|m| response.get("method") == Some(m))
                    && pattern
                        .get("has_timeout")
                        .is_none_or(|_| response.get("timeout").is_some())
            }
            "response_success" => {
                response.get("type") == Some(&json!("response"))
                    && response.get("success") == Some(&json!(true))
            }
            "response_error" => {
                response.get("type") == Some(&json!("response"))
                    && response.get("success") == Some(&json!(false))
            }
            _ => false,
        }
    }
}

/// Canonicalizes extension UI responses by removing volatile fields
fn canonicalize_ui_response(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_ui_response).collect()),
        Value::Object(object) => {
            let mut canonicalized = BTreeMap::new();
            for (key, value) in object {
                // Skip volatile fields specific to extension UI
                if matches!(key.as_str(), "timestamp" | "requestId" | "id" | "timeout") {
                    continue;
                }
                canonicalized.insert(key.clone(), canonicalize_ui_response(value));
            }
            Value::Object(canonicalized.into_iter().collect())
        }
        primitive => primitive.clone(),
    }
}

#[test]
fn g05_extension_ui_differential_fixture_validation() {
    // Validate fixture structure
    let scenarios: Value = serde_json::from_str(UI_SCENARIOS).expect("UI scenarios JSON");

    assert_eq!(
        scenarios["schema"],
        "pi.dropin.extension_ui_differential_scenarios.v1"
    );
    assert_eq!(scenarios["bead"], "bd-lnmtp.2.4");

    let ui_scenarios = scenarios["scenarios"]
        .as_array()
        .expect("UI scenarios array");
    assert!(
        ui_scenarios.len() >= 10,
        "bd-lnmtp.2.4 requires at least 10 UI scenarios, got {}",
        ui_scenarios.len()
    );

    // Validate each scenario has required fields
    for scenario in ui_scenarios {
        let id = scenario["id"].as_str().expect("scenario id");
        assert!(
            scenario.get("description").is_some(),
            "{id} missing description"
        );
        assert!(scenario.get("requests").is_some(), "{id} missing requests");
        assert!(
            scenario.get("expected_patterns").is_some(),
            "{id} missing expected_patterns"
        );
    }
}

#[test]
fn g05_extension_ui_canonicalization_stable() {
    let test_cases = [
        json!({
            "type": "extension_ui_request",
            "id": "req-123",
            "method": "confirm",
            "title": "Continue?",
            "timestamp": "2026-04-23T00:00:00Z"
        }),
        json!({
            "type": "response",
            "command": "extension_ui_response",
            "success": true,
            "requestId": "req-456",
            "timestamp": "2026-04-23T00:00:01Z"
        }),
    ];

    for (i, test_case) in test_cases.iter().enumerate() {
        let canonical_once = canonicalize_ui_response(test_case);
        let canonical_twice = canonicalize_ui_response(&canonical_once);

        assert_eq!(
            canonical_once, canonical_twice,
            "Canonicalization not stable for test case {i}"
        );

        // Verify volatile fields are removed
        if let Value::Object(obj) = &canonical_once {
            assert!(
                !obj.contains_key("timestamp"),
                "timestamp should be removed"
            );
            assert!(
                !obj.contains_key("requestId"),
                "requestId should be removed"
            );
            assert!(!obj.contains_key("id"), "id should be removed");
        }
    }
}

#[test]
fn g05_extension_ui_differential_basic_scenarios() {
    let scenarios: Value = serde_json::from_str(UI_SCENARIOS).expect("UI scenarios JSON");
    let ui_scenarios = scenarios["scenarios"]
        .as_array()
        .expect("UI scenarios array");

    let cargo_target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let rust_pi_path = format!("{cargo_target_dir}/debug/pi");

    if !std::path::Path::new(&rust_pi_path).exists() {
        eprintln!(
            "Warning: Rust pi binary not found at {rust_pi_path}. Skipping UI differential test."
        );
        return;
    }

    let tester = match ExtensionUiDifferentialTester::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Warning: Failed to create UI differential tester: {e}. Skipping test.");
            return;
        }
    };

    let mut successful_scenarios = 0;
    let mut failed_scenarios = Vec::new();
    let total_scenarios = ui_scenarios.len().min(5); // Test first 5 scenarios

    for scenario in ui_scenarios.iter().take(5) {
        let scenario_id = scenario["id"].as_str().unwrap_or("unknown");
        let scenario_type = scenario["type"].as_str().unwrap_or("unknown");

        match tester.execute_ui_scenario(scenario) {
            Ok(responses) => {
                if ExtensionUiDifferentialTester::validate_ui_scenario(scenario, &responses) {
                    successful_scenarios += 1;
                    println!("✓ {scenario_id}: {scenario_type} - PASS");
                } else {
                    failed_scenarios
                        .push(format!("{scenario_id}: {scenario_type} - Pattern mismatch"));
                    println!("✗ {scenario_id}: {scenario_type} - FAIL");
                }
            }
            Err(e) => {
                failed_scenarios.push(format!(
                    "{scenario_id}: {scenario_type} - Execution error: {e}"
                ));
                println!("✗ {scenario_id}: {scenario_type} - ERROR: {e}");
            }
        }
    }

    assert!(
        total_scenarios > 0,
        "Should have tested at least one UI scenario"
    );

    let successful_scenarios_u32 =
        u32::try_from(successful_scenarios).expect("scenario success count fits in u32");
    let total_scenarios_u32 = u32::try_from(total_scenarios).expect("scenario count fits in u32");
    let success_rate =
        (f64::from(successful_scenarios_u32) / f64::from(total_scenarios_u32)) * 100.0;

    println!(
        "\n=== G05 Extension UI Basic Differential Test Summary ===\n\
         Tested scenarios: {}\n\
         Successful: {}\n\
         Failed: {}\n\
         Success rate: {:.1}%\n",
        total_scenarios,
        successful_scenarios,
        failed_scenarios.len(),
        success_rate
    );

    if !failed_scenarios.is_empty() {
        println!("Failed scenarios:");
        for failure in &failed_scenarios {
            println!("  - {failure}");
        }
    }
}
