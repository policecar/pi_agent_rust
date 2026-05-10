use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SWARM_TEMP_DIR_SCHEMA: &str = "pi.doctor.swarm_temp_dir.v1";
const SWARM_TEMP_EXPECTED_ROOT: &str = "/data/tmp/pi_agent_rust_cargo";
const SWARM_TEMP_WARN_AVAILABLE_KB: u64 = 10 * 1024 * 1024;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct TestError(String);

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestError {}

fn fail<T>(message: impl Into<String>) -> TestResult<T> {
    Err(Box::new(TestError(message.into())))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition { Ok(()) } else { fail(message) }
}

fn require_eq<T, U>(actual: &T, expected: &U, context: &str) -> TestResult
where
    T: fmt::Debug + PartialEq<U> + ?Sized,
    U: fmt::Debug + ?Sized,
{
    if actual == expected {
        Ok(())
    } else {
        fail(format!("{context}: expected {expected:?}, got {actual:?}"))
    }
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| TestError(format!("missing JSON field `{key}` in {value}")))
        .map_err(Into::into)
}

fn field_str<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| TestError(format!("JSON field `{key}` is not a string in {value}")))
        .map_err(Into::into)
}

fn field_bool(value: &Value, key: &str) -> TestResult<bool> {
    field(value, key)?
        .as_bool()
        .ok_or_else(|| TestError(format!("JSON field `{key}` is not a bool in {value}")))
        .map_err(Into::into)
}

fn field_u64(value: &Value, key: &str) -> TestResult<u64> {
    field(value, key)?
        .as_u64()
        .ok_or_else(|| TestError(format!("JSON field `{key}` is not a u64 in {value}")))
        .map_err(Into::into)
}

fn run_doctor_json(env_overrides: &[(&str, Option<&str>)]) -> TestResult<Value> {
    let cwd = create_swarm_temp_test_dir(Path::new("/tmp"), "cwd")?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_pi")); // ubs:ignore false positive: Cargo provides the compiled test binary path.
    command
        .args(["doctor", "--only", "swarm", "--format", "json"])
        .current_dir(cwd)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("GEMINI_API_KEY")
        .env_remove("GROQ_API_KEY")
        .env_remove("KIMI_API_KEY")
        .env_remove("AZURE_OPENAI_API_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env_overrides {
        match value {
            Some(value) => {
                command.env(*key, *value);
            }
            None => {
                command.env_remove(*key);
            }
        }
    }

    let output = command.output()?;
    let exit_code = output.status.code();
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !matches!(exit_code, Some(0 | 1)) {
        return fail(format!(
            "doctor should exit cleanly with 0 or 1, got {exit_code:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        ));
    }

    serde_json::from_str(&stdout).map_err(|err| {
        TestError(format!(
            "doctor stdout should be JSON: {err}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        ))
        .into()
    })
}

fn temp_dir_finding<'a>(report: &'a Value, env_name: &str) -> TestResult<&'a Value> {
    let findings = field(report, "findings")?
        .as_array()
        .ok_or_else(|| TestError(format!("doctor findings is not an array in {report}")))?;
    for finding in findings {
        let Some(data) = finding.get("data") else {
            continue;
        };
        let schema = data.get("schema").and_then(Value::as_str);
        let finding_env_name = data.get("env_name").and_then(Value::as_str);
        if schema == Some(SWARM_TEMP_DIR_SCHEMA) && finding_env_name == Some(env_name) {
            return Ok(finding);
        }
    }

    fail(format!(
        "missing swarm temp-dir finding for {env_name}: {report}"
    ))
}

fn require_temp_dir_data_shape(data: &Value, env_name: &str) -> TestResult {
    require_eq(field_str(data, "schema")?, SWARM_TEMP_DIR_SCHEMA, "schema")?;
    require_eq(field_str(data, "env_name")?, env_name, "env_name")?;
    require_eq(
        field_str(data, "expected_root")?,
        SWARM_TEMP_EXPECTED_ROOT,
        "expected_root",
    )?;
    require_eq(
        &field_u64(data, "warn_available_kb")?,
        &SWARM_TEMP_WARN_AVAILABLE_KB,
        "warn_available_kb",
    )?;
    let _ = field(data, "path")?;
    let _ = field(data, "exists")?;
    let _ = field(data, "under_expected_root")?;
    let _ = field(data, "available_kb")?;
    require(
        field_str(data, "recommended_pattern")?.contains(SWARM_TEMP_EXPECTED_ROOT),
        format!("recommended_pattern should mention expected root: {data}"),
    )
}

fn require_available_kb_shape(data: &Value) -> TestResult {
    let value = field(data, "available_kb")?;
    require(
        value.is_null() || value.as_u64().is_some(),
        format!("available_kb should be null or an integer: {data}"),
    )
}

fn create_swarm_temp_test_dir(root: &Path, name: &str) -> TestResult<PathBuf> {
    let dir = root
        .join("pi-doctor-json-e2e")
        .join(format!("{}-{name}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn create_expected_root_test_dir(name: &str) -> TestResult<(PathBuf, bool)> {
    let dir = Path::new(SWARM_TEMP_EXPECTED_ROOT)
        .join("pi-doctor-json-e2e")
        .join(format!("{}-{name}", std::process::id()));
    match fs::create_dir_all(&dir) {
        Ok(()) => Ok((dir, true)),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => Ok((dir, false)),
        Err(err) => Err(err.into()),
    }
}

fn require_missing_env(report: &Value, env_name: &str) -> TestResult {
    let finding = temp_dir_finding(report, env_name)?;
    let data = field(finding, "data")?;
    require_eq(field_str(finding, "severity")?, "warn", "severity")?;
    require_eq(
        field_str(finding, "title")?,
        format!("{env_name} is not set").as_str(),
        "title",
    )?;
    require_temp_dir_data_shape(data, env_name)?;
    require(field(data, "path")?.is_null(), "missing env path is null")?;
    require_eq(&field_bool(data, "exists")?, &false, "exists")?;
    require(
        field(data, "under_expected_root")?.is_null(),
        "missing env root posture is null",
    )?;
    require(
        field(data, "available_kb")?.is_null(),
        "missing env available_kb is null",
    )
}

#[test]
fn doctor_swarm_temp_dir_json_reports_missing_env() -> TestResult {
    let report = run_doctor_json(&[("CARGO_TARGET_DIR", None), ("TMPDIR", None)])?;

    require_missing_env(&report, "CARGO_TARGET_DIR")?;
    require_missing_env(&report, "TMPDIR")
}

#[test]
fn doctor_swarm_temp_dir_json_freezes_root_posture() -> TestResult {
    let (expected_target, expected_target_exists) =
        create_expected_root_test_dir("expected-target")?;
    let outside_tmp = create_swarm_temp_test_dir(Path::new("/tmp"), "outside-tmp")?;
    let expected_target = expected_target.display().to_string();
    let outside_tmp = outside_tmp.display().to_string();
    let report = run_doctor_json(&[
        ("CARGO_TARGET_DIR", Some(expected_target.as_str())),
        ("TMPDIR", Some(outside_tmp.as_str())),
    ])?;

    let target_finding = temp_dir_finding(&report, "CARGO_TARGET_DIR")?;
    if expected_target_exists {
        require_eq(
            field_str(target_finding, "severity")?,
            "pass",
            "target severity",
        )?;
    } else {
        require_eq(
            field_str(target_finding, "severity")?,
            "warn",
            "target severity",
        )?;
        require(
            field_str(target_finding, "title")?.contains("does not point to a directory"),
            format!(
                "CARGO_TARGET_DIR should warn when expected root is unwritable: {target_finding}"
            ),
        )?;
    }
    let target_data = field(target_finding, "data")?;
    require_temp_dir_data_shape(target_data, "CARGO_TARGET_DIR")?;
    require_eq(
        field_str(target_data, "path")?,
        expected_target.as_str(),
        "target path",
    )?;
    require_eq(
        &field_bool(target_data, "exists")?,
        &expected_target_exists,
        "target exists",
    )?;
    require_eq(
        &field_bool(target_data, "under_expected_root")?,
        &true,
        "target under_expected_root",
    )?;
    if expected_target_exists {
        require_available_kb_shape(target_data)?;
    } else {
        require(
            field(target_data, "available_kb")?.is_null(),
            "uncreated target available_kb is null",
        )?;
    }

    let tmp_finding = temp_dir_finding(&report, "TMPDIR")?;
    require_eq(field_str(tmp_finding, "severity")?, "warn", "tmp severity")?;
    let tmp_data = field(tmp_finding, "data")?;
    require_temp_dir_data_shape(tmp_data, "TMPDIR")?;
    require_eq(
        field_str(tmp_data, "path")?,
        outside_tmp.as_str(),
        "tmp path",
    )?;
    require_eq(&field_bool(tmp_data, "exists")?, &true, "tmp exists")?;
    require_eq(
        &field_bool(tmp_data, "under_expected_root")?,
        &false,
        "tmp under_expected_root",
    )?;
    require_available_kb_shape(tmp_data)
}
