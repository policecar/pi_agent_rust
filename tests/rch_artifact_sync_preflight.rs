#![forbid(unsafe_code)]

use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REQUIRED_ARTIFACT: &str = "tests/ext_conformance/artifacts/PROVENANCE_VERIFICATION.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path() -> PathBuf {
    repo_root().join("scripts/check_rch_artifact_sync.py")
}

fn output_debug(output: &Output) -> String {
    format!(
        "status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn run_preflight(repo: &Path, required_path: &str) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new("python3")
        .arg(script_path())
        .arg("--repo-root")
        .arg(repo)
        .arg("--ignore-file")
        .arg(repo.join(".rchignore"))
        .arg("--required-path")
        .arg(required_path)
        .arg("--json")
        .output()?)
}

fn parse_json(output: &Output) -> Result<Value, Box<dyn Error>> {
    serde_json::from_slice(&output.stdout).map_err(|error| {
        test_error(format!(
            "preflight output should be JSON: {error}\n{}",
            output_debug(output)
        ))
    })
}

fn object_field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing JSON field: {key}")))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    object_field(value, key)?
        .as_str()
        .ok_or_else(|| test_error(format!("JSON field is not a string: {key}")))
}

fn i64_field(value: &Value, key: &str) -> Result<i64, Box<dyn Error>> {
    object_field(value, key)?
        .as_i64()
        .ok_or_else(|| test_error(format!("JSON field is not an integer: {key}")))
}

fn u64_field(value: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    object_field(value, key)?
        .as_u64()
        .ok_or_else(|| test_error(format!("JSON field is not an unsigned integer: {key}")))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    object_field(value, key)?
        .as_array()
        .ok_or_else(|| test_error(format!("JSON field is not an array: {key}")))
}

fn require_string_field(value: &Value, key: &str, expected: &str) -> Result<(), Box<dyn Error>> {
    match string_field(value, key)? {
        actual if actual.eq(expected) => Ok(()),
        actual => Err(test_error(format!(
            "expected JSON field {key} to be {expected:?}, got {actual:?}"
        ))),
    }
}

fn require_u64_field(value: &Value, key: &str, expected: u64) -> Result<(), Box<dyn Error>> {
    match u64_field(value, key)? {
        actual if actual == expected => Ok(()),
        actual => Err(test_error(format!(
            "expected JSON field {key} to be {expected}, got {actual}"
        ))),
    }
}

fn write_required_artifact(repo: &Path) -> Result<(), Box<dyn Error>> {
    let artifact = repo.join(REQUIRED_ARTIFACT);
    let parent = artifact
        .parent()
        .ok_or_else(|| test_error("required artifact path should have a parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(artifact, "{\"schema\":\"fixture\"}\n")?;
    Ok(())
}

#[test]
fn unanchored_artifacts_ignore_blocks_nested_required_artifacts() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let repo = temp.path();
    write_required_artifact(repo)?;
    fs::write(repo.join(".rchignore"), "artifacts/\nartifacts/**\n")?;

    let output = run_preflight(repo, REQUIRED_ARTIFACT)?;
    if output.status.success() {
        return Err(test_error(format!(
            "unanchored artifact rules should fail the preflight\n{}",
            output_debug(&output)
        )));
    }

    let report = parse_json(&output)?;
    require_string_field(&report, "schema", "pi.rch.artifact_sync_preflight.v1")?;
    require_string_field(&report, "status", "fail")?;

    let violations = array_field(&report, "violations")?;
    let has_expected_diagnostic = violations.iter().any(|violation| {
        matches!(
            (
                string_field(violation, "path"),
                string_field(violation, "source"),
                i64_field(violation, "line"),
                string_field(violation, "pattern"),
                string_field(violation, "reason"),
            ),
            (
                Ok(REQUIRED_ARTIFACT),
                Ok(".rchignore"),
                Ok(2),
                Ok("artifacts/**"),
                Ok("required_path_excluded"),
            )
        )
    });
    if !has_expected_diagnostic {
        return Err(test_error(format!(
            "diagnostics should name the exact .rchignore rule at fault:\n{}",
            output_debug(&output)
        )));
    }

    Ok(())
}

#[test]
fn anchored_root_artifacts_ignore_keeps_nested_required_artifacts() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let repo = temp.path();
    write_required_artifact(repo)?;
    fs::write(repo.join(".rchignore"), "/artifacts/\n/artifacts/**\n")?;

    let output = run_preflight(repo, REQUIRED_ARTIFACT)?;
    if !output.status.success() {
        return Err(test_error(format!(
            "anchored root artifact rules must not hide nested test artifacts\n{}",
            output_debug(&output)
        )));
    }

    let report = parse_json(&output)?;
    require_string_field(&report, "status", "pass")?;
    let required_paths = array_field(&report, "required_paths")?;
    let first_required = required_paths
        .first()
        .ok_or_else(|| test_error("expected one required path entry"))?;
    let matched_rules = array_field(first_required, "matched_rules")?;
    if !matched_rules.is_empty() {
        return Err(test_error(format!(
            "anchored root rules should not match nested artifact path:\n{}",
            output_debug(&output)
        )));
    }

    Ok(())
}

#[test]
fn current_repo_required_artifacts_pass_sync_preflight() -> Result<(), Box<dyn Error>> {
    let output = Command::new("python3")
        .arg(script_path())
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--json")
        .output()?;

    if !output.status.success() {
        return Err(test_error(format!(
            "repo .rchignore should keep required artifact paths synced\n{}",
            output_debug(&output)
        )));
    }

    let report = parse_json(&output)?;
    require_string_field(&report, "status", "pass")?;
    let summary = object_field(&report, "summary")?;
    require_u64_field(summary, "violation_count", 0)?;
    Ok(())
}
