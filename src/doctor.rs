//! Comprehensive environment health checker for `pi doctor`.
//!
//! When invoked without a path, checks config, directories, auth, shell tools,
//! and sessions. When invoked with a path, runs extension preflight analysis.
//! With `--fix`, automatically repairs safe issues (missing dirs, permissions).

use crate::auth::{AuthStorage, CredentialStatus};
use crate::config::Config;
use crate::error::Result;
use crate::provider_metadata::provider_auth_env_keys;
use crate::resource_governor::{
    AdmissionAction, HostResourceBudgets, HostResourceSample, ResourceOperationKind,
    ResourceRequest, SwarmAdmissionController, SwarmCapacityDimension,
    SwarmCapacityEvidenceSummary, SwarmCapacityPlan, SwarmCapacityPlanError,
    SwarmCapacityPlannerConfig, SwarmHostInventory, SwarmLiveLoad, TailLatencyRegimeSample,
};
use crate::session::SessionHeader;
use crate::session_index::walk_sessions;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SWARM_STALE_IN_PROGRESS_HOURS: i64 = 24;
const SWARM_DETAIL_LIMIT: usize = 5;
const SWARM_DISK_WARN_AVAILABLE_KB: u64 = 10 * 1024 * 1024;
const SWARM_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SWARM_DOCTOR_ADMISSION_SCHEMA: &str = "pi.doctor.swarm_admission.v1";
const SWARM_DOCTOR_RCH_FAILURE_SCHEMA: &str = "pi.doctor.rch_failure.v1";
const SWARM_DOCTOR_TEMP_DIR_SCHEMA: &str = "pi.doctor.swarm_temp_dir.v1";
const SWARM_DOCTOR_BUILD_SLOT_SCHEMA: &str = "pi.doctor.agent_mail_build_slots.v1";
const SWARM_DOCTOR_CONTACTS_SCHEMA: &str = "pi.doctor.agent_mail_contacts.v1";
const SWARM_DOCTOR_STALLED_REAPER_SCHEMA: &str = "pi.doctor.stalled_bead_reaper.v1";
const SWARM_DOCTOR_NEXT_ACTION_SCHEMA: &str = "pi.doctor.communication_purgatory_next_action.v1";
const SWARM_DOCTOR_RESERVATION_HEATMAP_SCHEMA: &str =
    "pi.doctor.agent_mail_reservation_conflict_heatmap.v1";
const SWARM_CARGO_SCRATCH_ROOT: &str = "/data/tmp/pi_agent_rust_cargo";
const SWARM_BUILD_SLOT_SOON_EXPIRING_MINUTES: i64 = 30;
const SWARM_RESERVATION_RECENT_HOURS: i64 = 24;
const SWARM_RESERVATION_STALE_HOLDER_HOURS: i64 = 24;
const SWARM_RESERVATION_EXPIRING_SOON_MINUTES: i64 = 30;
const MIB_BYTES: u64 = 1024 * 1024;

// ── Core Types ──────────────────────────────────────────────────────

/// How severe a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Pass,
    Info,
    Warn,
    Fail,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// Whether a finding can be auto-fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fixability {
    /// Cannot be auto-fixed.
    NotFixable,
    /// Can be auto-fixed with `--fix`.
    AutoFixable,
    /// Was auto-fixed in this run.
    Fixed,
}

/// Which subsystem a check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckCategory {
    Config,
    Dirs,
    Auth,
    Shell,
    Sessions,
    Swarm,
    Extensions,
}

impl CheckCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::Config => "Configuration",
            Self::Dirs => "Directories",
            Self::Auth => "Authentication",
            Self::Shell => "Shell & Tools",
            Self::Sessions => "Sessions",
            Self::Swarm => "Swarm Coordination",
            Self::Extensions => "Extensions",
        }
    }
}

impl fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl std::str::FromStr for CheckCategory {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "config" => Ok(Self::Config),
            "dirs" | "directories" => Ok(Self::Dirs),
            "auth" | "authentication" => Ok(Self::Auth),
            "shell" => Ok(Self::Shell),
            "sessions" => Ok(Self::Sessions),
            "swarm" | "coordination" | "leases" => Ok(Self::Swarm),
            "extensions" | "ext" => Ok(Self::Extensions),
            other => Err(format!("unknown category: {other}")),
        }
    }
}

/// A single diagnostic finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: CheckCategory,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub fixability: Fixability,
}

impl Finding {
    fn pass(category: CheckCategory, title: impl Into<String>) -> Self {
        Self {
            category,
            severity: Severity::Pass,
            title: title.into(),
            detail: None,
            remediation: None,
            data: None,
            fixability: Fixability::NotFixable,
        }
    }

    fn info(category: CheckCategory, title: impl Into<String>) -> Self {
        Self {
            category,
            severity: Severity::Info,
            title: title.into(),
            detail: None,
            remediation: None,
            data: None,
            fixability: Fixability::NotFixable,
        }
    }

    fn warn(category: CheckCategory, title: impl Into<String>) -> Self {
        Self {
            category,
            severity: Severity::Warn,
            title: title.into(),
            detail: None,
            remediation: None,
            data: None,
            fixability: Fixability::NotFixable,
        }
    }

    fn fail(category: CheckCategory, title: impl Into<String>) -> Self {
        Self {
            category,
            severity: Severity::Fail,
            title: title.into(),
            detail: None,
            remediation: None,
            data: None,
            fixability: Fixability::NotFixable,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    const fn auto_fixable(mut self) -> Self {
        self.fixability = Fixability::AutoFixable;
        self
    }

    const fn fixed(mut self) -> Self {
        self.fixability = Fixability::Fixed;
        self.severity = Severity::Pass;
        self
    }
}

/// Summary counters.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DoctorSummary {
    pub pass: usize,
    pub info: usize,
    pub warn: usize,
    pub fail: usize,
}

/// Full diagnostic report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub findings: Vec<Finding>,
    pub summary: DoctorSummary,
    pub overall: Severity,
}

impl DoctorReport {
    fn from_findings(findings: Vec<Finding>) -> Self {
        let mut summary = DoctorSummary::default();
        let mut overall = Severity::Pass;
        for f in &findings {
            match f.severity {
                Severity::Pass => summary.pass += 1,
                Severity::Info => summary.info += 1,
                Severity::Warn => {
                    summary.warn += 1;
                    if overall < Severity::Warn {
                        overall = Severity::Warn;
                    }
                }
                Severity::Fail => {
                    summary.fail += 1;
                    overall = Severity::Fail;
                }
            }
        }
        Self {
            findings,
            summary,
            overall,
        }
    }

    /// Render human-friendly text output.
    pub fn render_text(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str("Pi Doctor\n=========\n");

        // Group findings by category, preserving insertion order
        let mut seen_categories: Vec<CheckCategory> = Vec::new();
        for f in &self.findings {
            if !seen_categories.contains(&f.category) {
                seen_categories.push(f.category);
            }
        }

        for cat in &seen_categories {
            let cat_findings: Vec<&Finding> = self
                .findings
                .iter()
                .filter(|f| f.category.eq(cat))
                .collect();
            let cat_worst = cat_findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Pass);
            let _ = writeln!(out, "\n[{cat_worst}] {cat}");
            for f in &cat_findings {
                let _ = writeln!(out, "  [{}] {}", f.severity, f.title);
                if let Some(detail) = &f.detail {
                    let _ = writeln!(out, "       {detail}");
                }
                if let Some(rem) = &f.remediation {
                    let _ = writeln!(out, "       Fix: {rem}");
                }
                if matches!(f.fixability, Fixability::AutoFixable) {
                    out.push_str("       (fixable with --fix)\n");
                }
            }
        }

        let _ = writeln!(
            out,
            "\nOverall: {} ({} pass, {} info, {} warn, {} fail)",
            self.overall,
            self.summary.pass,
            self.summary.info,
            self.summary.warn,
            self.summary.fail
        );
        out
    }

    /// Render as JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Render as markdown.
    pub fn render_markdown(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str("# Pi Doctor Report\n\n");

        let mut seen_categories: Vec<CheckCategory> = Vec::new();
        for f in &self.findings {
            if !seen_categories.contains(&f.category) {
                seen_categories.push(f.category);
            }
        }

        for cat in &seen_categories {
            let _ = writeln!(out, "## {cat}\n");
            for f in self.findings.iter().filter(|f| f.category.eq(cat)) {
                let icon = match f.severity {
                    Severity::Pass => "✅",
                    Severity::Info => "ℹ️",
                    Severity::Warn => "⚠️",
                    Severity::Fail => "❌",
                };
                let _ = write!(out, "- {icon} **{}**", f.title);
                if let Some(detail) = &f.detail {
                    let _ = write!(out, " — {detail}");
                }
                out.push('\n');
                if let Some(rem) = &f.remediation {
                    let _ = writeln!(out, "  - Fix: {rem}");
                }
            }
            out.push('\n');
        }

        let _ = writeln!(
            out,
            "**Overall: {}** ({} pass, {} info, {} warn, {} fail)",
            self.overall,
            self.summary.pass,
            self.summary.info,
            self.summary.warn,
            self.summary.fail
        );
        out
    }
}

// ── Options ─────────────────────────────────────────────────────────

/// Options for `run_doctor`.
pub struct DoctorOptions<'a> {
    pub cwd: &'a Path,
    pub extension_path: Option<&'a str>,
    pub policy_override: Option<&'a str>,
    pub fix: bool,
    pub only: Option<HashSet<CheckCategory>>,
}

// ── Entry Point ─────────────────────────────────────────────────────

/// Run all applicable doctor checks and return a report.
#[allow(clippy::too_many_lines)]
pub fn run_doctor(opts: &DoctorOptions<'_>) -> Result<DoctorReport> {
    let mut findings = Vec::new();
    let extension_only_default = opts.extension_path.is_some() && opts.only.is_none();

    let should_run = |cat: CheckCategory| -> bool {
        if extension_only_default {
            return false;
        }
        opts.only.as_ref().is_none_or(|set| set.contains(&cat))
    };

    if let Some(ext_path) = opts.extension_path {
        if opts
            .only
            .as_ref()
            .is_none_or(|set| set.contains(&CheckCategory::Extensions))
        {
            check_extension(opts.cwd, ext_path, opts.policy_override, &mut findings);
        }
    } else if opts
        .only
        .as_ref()
        .is_some_and(|set| set.contains(&CheckCategory::Extensions))
    {
        findings.push(
            Finding::fail(
                CheckCategory::Extensions,
                "Extensions check requires an extension path",
            )
            .with_remediation(
                "Run `pi doctor <path-to-extension>` to evaluate extension compatibility",
            ),
        );
    }

    if should_run(CheckCategory::Config) {
        check_config(opts.cwd, &mut findings);
    }
    if should_run(CheckCategory::Dirs) {
        check_dirs(opts.fix, &mut findings);
    }
    if should_run(CheckCategory::Auth) {
        check_auth(opts.fix, &mut findings);
    }
    if should_run(CheckCategory::Shell) {
        check_shell(&mut findings);
    }
    if should_run(CheckCategory::Sessions) {
        check_sessions(&mut findings);
    }
    if should_run(CheckCategory::Swarm) {
        check_swarm(opts.cwd, &mut findings);
    }

    Ok(DoctorReport::from_findings(findings))
}

// ── Check: Config ───────────────────────────────────────────────────

fn check_config(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Config;

    // Global settings
    let global_path = Config::global_dir().join("settings.json");
    check_settings_file(cat, &global_path, "Global settings", findings);

    // Project settings
    let project_path = cwd.join(Config::project_dir()).join("settings.json");
    if project_path.exists() {
        check_settings_file(
            cat,
            &project_path,
            "Project settings (.pi/settings.json)",
            findings,
        );
    } else {
        findings.push(Finding::pass(cat, "No project settings (OK)"));
    }
}

fn check_settings_file(cat: CheckCategory, path: &Path, label: &str, findings: &mut Vec<Finding>) {
    if !path.exists() {
        findings.push(Finding::pass(cat, format!("{label}: not present (OK)")));
        return;
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let value: serde_json::Value = match serde_json::from_str(&content) {
                Ok(value) => value,
                Err(e) => {
                    findings.push(
                        Finding::fail(cat, format!("{label}: JSON parse error"))
                            .with_detail(e.to_string())
                            .with_remediation(format!("Fix the JSON syntax in {}", path.display())),
                    );
                    return;
                }
            };

            let serde_json::Value::Object(map) = value else {
                findings.push(
                    Finding::fail(
                        cat,
                        format!("{label}: top-level value must be a JSON object"),
                    )
                    .with_detail(format!("Found non-object JSON in {}", path.display()))
                    .with_remediation(format!("Wrap settings in {{ ... }} in {}", path.display())),
                );
                return;
            };

            let unknown: Vec<&String> = map.keys().filter(|k| !is_known_config_key(k)).collect();
            if unknown.is_empty() {
                findings.push(Finding::pass(cat, label.to_string()));
            } else {
                findings.push(
                    Finding::warn(cat, format!("{label}: unknown keys"))
                        .with_detail(format!(
                            "Unknown keys: {}",
                            unknown
                                .iter()
                                .map(|k| k.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                        .with_remediation("Check for typos in settings key names"),
                );
            }
        }
        Err(e) => {
            findings.push(
                Finding::fail(cat, format!("{label}: read error"))
                    .with_detail(e.to_string())
                    .with_remediation(format!("Check file permissions on {}", path.display())),
            );
        }
    }
}

/// Known top-level config keys (from `Config` struct fields + their camelCase aliases).
fn is_known_config_key(key: &str) -> bool {
    matches!(
        key,
        "theme"
            | "hideThinkingBlock"
            | "hide_thinking_block"
            | "showHardwareCursor"
            | "show_hardware_cursor"
            | "defaultProvider"
            | "default_provider"
            | "defaultModel"
            | "default_model"
            | "defaultThinkingLevel"
            | "default_thinking_level"
            | "enabledModels"
            | "enabled_models"
            | "steeringMode"
            | "steering_mode"
            | "followUpMode"
            | "follow_up_mode"
            | "quietStartup"
            | "quiet_startup"
            | "collapseChangelog"
            | "collapse_changelog"
            | "lastChangelogVersion"
            | "last_changelog_version"
            | "doubleEscapeAction"
            | "double_escape_action"
            | "editorPaddingX"
            | "editor_padding_x"
            | "autocompleteMaxVisible"
            | "autocomplete_max_visible"
            | "sessionPickerInput"
            | "session_picker_input"
            | "sessionStore"
            | "sessionBackend"
            | "session_store"
            | "compaction"
            | "branchSummary"
            | "branch_summary"
            | "retry"
            | "shellPath"
            | "shell_path"
            | "shellCommandPrefix"
            | "shell_command_prefix"
            | "ghPath"
            | "gh_path"
            | "images"
            | "terminal"
            | "thinkingBudgets"
            | "thinking_budgets"
            | "packages"
            | "extensions"
            | "skills"
            | "prompts"
            | "themes"
            | "enableSkillCommands"
            | "enable_skill_commands"
            | "extensionPolicy"
            | "extension_policy"
            | "repairPolicy"
            | "repair_policy"
            | "extensionRisk"
            | "extension_risk"
            | "checkForUpdates"
            | "check_for_updates"
            | "sessionDurability"
            | "session_durability"
            | "markdown"
            | "queueMode"
    )
}

// ── Check: Dirs ─────────────────────────────────────────────────────

fn check_dirs(fix: bool, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Dirs;
    let dirs = [
        ("Agent directory", Config::global_dir()),
        ("Sessions directory", Config::sessions_dir()),
        ("Packages directory", Config::package_dir()),
    ];

    for (label, dir) in &dirs {
        check_dir(cat, label, dir, fix, findings);
    }
}

fn check_dir(cat: CheckCategory, label: &str, dir: &Path, fix: bool, findings: &mut Vec<Finding>) {
    if dir.is_dir() {
        // Check write permission
        match tempfile::NamedTempFile::new_in(dir) {
            Ok(mut probe_file) => match probe_file.write_all(b"probe") {
                Ok(()) => {
                    findings.push(Finding::pass(cat, format!("{label} ({})", dir.display())));
                }
                Err(e) => {
                    findings.push(
                        Finding::fail(cat, format!("{label}: not writable"))
                            .with_detail(format!("{}: {e}", dir.display()))
                            .with_remediation(format!("chmod u+w {}", dir.display())),
                    );
                }
            },
            Err(e) => {
                findings.push(
                    Finding::fail(cat, format!("{label}: not writable"))
                        .with_detail(format!("{}: {e}", dir.display()))
                        .with_remediation(format!("chmod u+w {}", dir.display())),
                );
            }
        }
    } else if fix {
        match std::fs::create_dir_all(dir) {
            Ok(()) => {
                findings.push(
                    Finding::pass(cat, format!("{label}: created ({})", dir.display())).fixed(),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::fail(cat, format!("{label}: could not create"))
                        .with_detail(format!("{}: {e}", dir.display()))
                        .with_remediation(format!("mkdir -p {}", dir.display())),
                );
            }
        }
    } else {
        findings.push(
            Finding::warn(cat, format!("{label}: missing"))
                .with_detail(format!("{} does not exist", dir.display()))
                .with_remediation(format!("mkdir -p {}", dir.display()))
                .auto_fixable(),
        );
    }
}

// ── Check: Auth ─────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
#[cfg_attr(not(unix), allow(unused_variables))]
fn check_auth(fix: bool, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Auth;
    let auth_path = Config::auth_path();

    if !auth_path.exists() {
        findings.push(
            Finding::info(cat, "auth.json: not present")
                .with_detail("No credentials stored yet")
                .with_remediation("Run `pi` and follow the login prompt, or set ANTHROPIC_API_KEY"),
        );
        // Still check env vars
        check_auth_env_vars(cat, findings);
        return;
    }

    // Check if auth.json parses
    let auth = match AuthStorage::load(auth_path.clone()) {
        Ok(auth) => {
            findings.push(Finding::pass(cat, "auth.json parses correctly"));
            Some(auth)
        }
        Err(e) => {
            findings.push(
                Finding::fail(cat, "auth.json: parse error")
                    .with_detail(e.to_string())
                    .with_remediation("Check auth.json syntax or delete and re-authenticate"),
            );
            None
        }
    };

    // Check file permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&auth_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode.eq(&0o600) {
                findings.push(Finding::pass(cat, "auth.json permissions (600)"));
            } else if fix {
                match std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => {
                        findings.push(
                            Finding::pass(
                                cat,
                                format!("auth.json permissions fixed (was {mode:o}, now 600)"),
                            )
                            .fixed(),
                        );
                    }
                    Err(e) => {
                        findings.push(
                            Finding::fail(cat, "auth.json: could not fix permissions")
                                .with_detail(e.to_string()),
                        );
                    }
                }
            } else {
                findings.push(
                    Finding::warn(
                        cat,
                        format!("auth.json permissions are {mode:o}, should be 600"),
                    )
                    .with_remediation(format!("chmod 600 {}", auth_path.display()))
                    .auto_fixable(),
                );
            }
        }
    }

    // Check stored credentials
    if let Some(auth) = &auth {
        let providers = auth.provider_names();
        if providers.is_empty() {
            findings.push(
                Finding::info(cat, "No stored credentials")
                    .with_remediation("Run `pi` to authenticate or set an API key env var"),
            );
        } else {
            for provider in &providers {
                let status = auth.credential_status(provider);
                match status {
                    CredentialStatus::ApiKey => {
                        findings.push(Finding::pass(
                            cat,
                            format!("{provider}: API key configured"),
                        ));
                    }
                    CredentialStatus::OAuthValid { .. } => {
                        findings.push(Finding::pass(cat, format!("{provider}: OAuth token valid")));
                    }
                    CredentialStatus::OAuthExpired { .. } => {
                        findings.push(
                            Finding::warn(cat, format!("{provider}: OAuth token expired"))
                                .with_remediation(format!("Run `pi /login {provider}` to refresh")),
                        );
                    }
                    CredentialStatus::BearerToken => {
                        findings.push(Finding::pass(
                            cat,
                            format!("{provider}: bearer token configured"),
                        ));
                    }
                    CredentialStatus::AwsCredentials => {
                        findings.push(Finding::pass(
                            cat,
                            format!("{provider}: AWS credentials configured"),
                        ));
                    }
                    CredentialStatus::ServiceKey => {
                        findings.push(Finding::pass(
                            cat,
                            format!("{provider}: service key configured"),
                        ));
                    }
                    CredentialStatus::Missing => {
                        // Shouldn't happen since we're iterating stored providers
                        findings.push(Finding::info(cat, format!("{provider}: no credentials")));
                    }
                }
            }
        }
    }

    check_auth_env_vars(cat, findings);
}

/// Check common auth-related environment variables.
fn check_auth_env_vars(cat: CheckCategory, findings: &mut Vec<Finding>) {
    let key_providers = [
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("google", "GOOGLE_API_KEY"),
    ];

    for (provider, env_key) in &key_providers {
        let env_keys = provider_auth_env_keys(provider);
        let has_env = env_keys.iter().any(|k| std::env::var(k).is_ok());
        if has_env {
            findings.push(Finding::pass(
                cat,
                format!("{provider}: env var set ({env_key})"),
            ));
        } else {
            findings.push(
                Finding::info(cat, format!("{provider}: no env var"))
                    .with_detail(format!("Set {env_key} or run `pi /login {provider}`")),
            );
        }
    }
}

// ── Check: Shell ────────────────────────────────────────────────────

fn check_shell(findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Shell;

    // Required tools (Fail if missing)
    check_tool(
        cat,
        "bash",
        &["--version"],
        Severity::Fail,
        ToolCheckMode::PresenceOnly,
        findings,
    );
    check_tool(
        cat,
        "sh",
        &["--version"],
        Severity::Fail,
        ToolCheckMode::PresenceOnly,
        findings,
    );

    // Important tools (Warn if missing)
    check_tool(
        cat,
        "git",
        &["--version"],
        Severity::Warn,
        ToolCheckMode::PresenceOnly,
        findings,
    );
    check_tool(
        cat,
        "rg",
        &["--version"],
        Severity::Warn,
        ToolCheckMode::PresenceOnly,
        findings,
    );

    let fd_bin = if which_tool("fd").is_some() {
        "fd"
    } else {
        "fdfind"
    };
    check_tool(
        cat,
        fd_bin,
        &["--version"],
        Severity::Warn,
        ToolCheckMode::PresenceOnly,
        findings,
    );

    // Optional tools (Info if missing)
    check_tool(
        cat,
        "gh",
        &["--version"],
        Severity::Info,
        ToolCheckMode::PresenceOnly,
        findings,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolCheckMode {
    PresenceOnly,
    ProbeExecution,
}

fn check_tool(
    cat: CheckCategory,
    tool: &str,
    args: &[&str],
    missing_severity: Severity,
    mode: ToolCheckMode,
    findings: &mut Vec<Finding>,
) {
    let discovered_path = which_tool(tool);
    if matches!(mode, ToolCheckMode::PresenceOnly) {
        if let Some(path) = discovered_path {
            findings.push(Finding::pass(cat, format!("{tool} ({path})")));
            return;
        }
        report_missing_tool(cat, tool, missing_severity, findings);
        return;
    }

    let command_target = discovered_path.as_deref().unwrap_or(tool);

    let mut command = Command::new(command_target); // ubs:ignore false positive: private doctor tool probe; production callers pass fixed tool names.
    match command
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            // Extract version from first line of stdout
            let version = String::from_utf8_lossy(&output.stdout);
            let first_line = version.lines().next().unwrap_or("").trim();
            let label = discovered_path.as_ref().map_or_else(
                || {
                    if first_line.is_empty() {
                        tool.to_string()
                    } else {
                        format!("{tool}: {first_line}")
                    }
                },
                |path| format!("{tool} ({path})"),
            );
            findings.push(Finding::pass(cat, label));
        }
        Ok(output)
            if discovered_path.is_some()
                && probe_failure_is_known_nonfatal(tool, args, &output) =>
        {
            // Some shells (e.g. dash as /bin/sh) do not support --version.
            // If this is the known non-fatal probe case, treat tool as present.
            let path = discovered_path.unwrap_or_default();
            findings.push(Finding::pass(cat, format!("{tool} ({path})")));
        }
        Ok(output) => {
            let suffix = if matches!(missing_severity, Severity::Info) {
                " (optional)"
            } else {
                ""
            };
            let detail = {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if stderr.is_empty() {
                    format!("Exit status: {:?}", output.status.code())
                } else {
                    stderr
                }
            };
            findings.push(Finding {
                category: cat,
                severity: missing_severity,
                title: format!("{tool}: invocation failed{suffix}"),
                detail: Some(detail),
                remediation: discovered_path
                    .as_ref()
                    .map(|path| format!("Verify this executable is healthy: {path}")),
                data: None,
                fixability: Fixability::NotFixable,
            });
        }
        Err(err) => {
            if discovered_path.is_some() || !matches!(err.kind(), std::io::ErrorKind::NotFound) {
                let suffix = if matches!(missing_severity, Severity::Info) {
                    " (optional)"
                } else {
                    ""
                };
                findings.push(Finding {
                    category: cat,
                    severity: missing_severity,
                    title: format!("{tool}: invocation failed{suffix}"),
                    detail: Some(err.to_string()),
                    remediation: discovered_path
                        .as_ref()
                        .map(|path| format!("Verify this executable is healthy: {path}")),
                    data: None,
                    fixability: Fixability::NotFixable,
                });
            } else {
                report_missing_tool(cat, tool, missing_severity, findings);
            }
        }
    }
}

fn report_missing_tool(
    cat: CheckCategory,
    tool: &str,
    missing_severity: Severity,
    findings: &mut Vec<Finding>,
) {
    let suffix = if matches!(missing_severity, Severity::Info) {
        " (optional)"
    } else {
        ""
    };
    let mut f = Finding {
        category: cat,
        severity: missing_severity,
        title: format!("{tool}: not found{suffix}"),
        detail: None,
        remediation: None,
        data: None,
        fixability: Fixability::NotFixable,
    };
    if tool.eq("gh") {
        f.remediation = Some("Install: https://cli.github.com/".to_string());
    }
    findings.push(f);
}

fn probe_failure_is_known_nonfatal(
    tool: &str,
    args: &[&str],
    output: &std::process::Output,
) -> bool {
    if tool.ne("sh") || args.ne(&["--version"]) {
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stderr.contains("illegal option")
        || stderr.contains("unknown option")
        || stderr.contains("invalid option")
}

fn which_tool(tool: &str) -> Option<String> {
    let tool_path = Path::new(tool);
    if tool_path.components().count() > 1 {
        return is_executable(tool_path).then(|| tool_path.display().to_string());
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if let Some(path) = resolve_executable_in_dir(&dir, tool) {
            return Some(path.display().to_string());
        }
    }
    None
}

fn resolve_executable_in_dir(dir: &Path, tool: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let candidate = dir.join(tool);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        let pathext = std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
        for ext in std::env::split_paths(&pathext) {
            let ext = ext.to_string_lossy();
            let suffix = ext.trim_matches('.');
            if suffix.is_empty() {
                continue;
            }
            let candidate = dir.join(format!("{tool}.{suffix}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    #[cfg(not(windows))]
    {
        let candidate = dir.join(tool);
        is_executable(&candidate).then_some(candidate)
    }
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .ok()
            .is_some_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

// ── Check: Swarm Coordination ───────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn check_swarm(cwd: &Path, findings: &mut Vec<Finding>) {
    check_swarm_beads(cwd, findings);
    check_swarm_live_admission(cwd, findings);
    check_swarm_br_status(cwd, findings);
    check_swarm_agent_mail(cwd, findings);
    check_swarm_stalled_bead_reaper(cwd, findings);
    check_swarm_next_action(cwd, findings);
    check_swarm_git(cwd, findings);
    check_swarm_rch(findings);
    check_swarm_temp_dirs(findings);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BeadsLedgerSummary {
    total: usize,
    open: usize,
    in_progress: usize,
    active: usize,
    parse_errors: usize,
    stale_in_progress: Vec<StaleIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleIssue {
    id: String,
    title: String,
    updated_at: String,
    age_hours: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct BeadsIssueRecord {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default, alias = "type")]
    issue_type: Option<String>,
    status: String,
    updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentMailActivity {
    last_active_ts: String,
    age_hours: i64,
}

fn check_swarm_beads(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    let ledger_path = cwd.join(".beads/issues.jsonl");
    if !ledger_path.is_file() {
        findings.push(
            Finding::warn(cat, "Beads ledger not found")
                .with_detail(format!("Expected {}", ledger_path.display()))
                .with_remediation("Run from a Beads-backed checkout or initialize Beads first"),
        );
        return;
    }

    let content = match std::fs::read_to_string(&ledger_path) {
        Ok(content) => content,
        Err(err) => {
            findings.push(
                Finding::fail(cat, "Beads ledger is not readable")
                    .with_detail(format!("{}: {err}", ledger_path.display()))
                    .with_remediation("Check ledger permissions before starting more agents"),
            );
            return;
        }
    };

    let summary = summarize_beads_ledger(&content, Utc::now(), SWARM_STALE_IN_PROGRESS_HOURS);
    if summary.parse_errors.eq(&0) {
        findings.push(
            Finding::pass(cat, "Beads ledger parses").with_detail(format!(
                "{} issues; {} active ({} open, {} in_progress)",
                summary.total, summary.active, summary.open, summary.in_progress
            )),
        );
    } else {
        findings.push(
            Finding::fail(cat, "Beads ledger has malformed JSONL rows")
                .with_detail(format!(
                    "{} parse error(s) in {} rows",
                    summary.parse_errors, summary.total
                ))
                .with_remediation("Run `br doctor --json` and rebuild from healthy issues.jsonl before claiming more work"),
        );
    }

    if summary.stale_in_progress.is_empty() {
        findings.push(Finding::pass(cat, "No stale in_progress beads detected"));
    } else {
        findings.push(
            Finding::warn(cat, "Stale in_progress beads need coordination")
                .with_detail(format_stale_issues(&summary.stale_in_progress))
                .with_remediation("Use Agent Mail to contact owners; only reset a bead after confirming the owner is stale"),
        );
    }
}

fn check_swarm_stalled_bead_reaper(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    let ledger_path = cwd.join(".beads/issues.jsonl");
    let content = match std::fs::read_to_string(&ledger_path) {
        Ok(content) => content,
        Err(err) => {
            findings.push(
                Finding::warn(cat, "Stalled bead reaper audit unavailable")
                    .with_detail(format!("{}: {err}", ledger_path.display()))
                    .with_remediation(
                        "Run `br list --status=in_progress --json` manually before resetting beads",
                    ),
            );
            return;
        }
    };

    let (agent_roster, agent_roster_error) = read_agent_mail_agents_roster(cwd);
    let finding = classify_stalled_bead_reaper(
        &content,
        agent_roster.as_ref(),
        agent_roster_error.as_deref(),
        Utc::now(),
        SWARM_STALE_IN_PROGRESS_HOURS,
    );
    findings.push(finding);
}

fn read_agent_mail_agents_roster(cwd: &Path) -> (Option<serde_json::Value>, Option<String>) {
    if which_tool("am").is_none() {
        return (None, Some("Agent Mail CLI not found".to_string()));
    }

    let project = cwd.display().to_string();
    let args = [
        "robot",
        "agents",
        "--format",
        "json",
        "--project",
        project.as_str(),
    ];
    match run_tool_with_timeout(SwarmProbeCommand::Am, &args, Some(cwd), SWARM_PROBE_TIMEOUT) {
        Ok(outcome) if outcome.timed_out => (
            None,
            Some("am robot agents timed out before returning activity data".to_string()),
        ),
        Ok(outcome) if !outcome.success => (
            None,
            Some(format!(
                "am robot agents unavailable: {}",
                command_failure_detail(&outcome)
            )),
        ),
        Ok(outcome) => match serde_json::from_str::<serde_json::Value>(&outcome.stdout) {
            Ok(value) => (Some(value), None),
            Err(err) => (
                None,
                Some(format!(
                    "am robot agents returned non-JSON output: {err}; {}",
                    redacted_output_snippet(&outcome)
                )),
            ),
        },
        Err(err) => (
            None,
            Some(format!("am robot agents failed to start: {err}")),
        ),
    }
}

fn check_swarm_live_admission(cwd: &Path, findings: &mut Vec<Finding>) {
    let ledger_path = cwd.join(".beads/issues.jsonl");
    let content = match std::fs::read_to_string(&ledger_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let warnings = vec!["Beads ledger missing".to_string()];
            findings.push(swarm_admission_blocked_finding(
                Severity::Warn,
                "Live swarm admission decision denies new work",
                format!("Beads ledger not found at {}", ledger_path.display()),
                &warnings,
            ));
            return;
        }
        Err(err) => {
            let warnings = vec!["Beads ledger unreadable".to_string()];
            findings.push(swarm_admission_blocked_finding(
                Severity::Fail,
                "Live swarm admission decision unavailable",
                format!("{} is not readable: {err}", ledger_path.display()),
                &warnings,
            ));
            return;
        }
    };

    let summary = summarize_beads_ledger(&content, Utc::now(), SWARM_STALE_IN_PROGRESS_HOURS);
    if summary.parse_errors > 0 {
        let warnings = vec!["Beads ledger has malformed JSONL rows".to_string()];
        findings.push(swarm_admission_blocked_finding(
            Severity::Fail,
            "Live swarm admission decision denies new work",
            format!(
                "Beads ledger has {} malformed JSONL row(s); coordination state is corrupted",
                summary.parse_errors
            ),
            &warnings,
        ));
        return;
    }

    let sample = HostResourceSample::current();
    let mut warnings = resource_sample_warnings(&sample);
    if !summary.stale_in_progress.is_empty() {
        warnings.push(format!(
            "{} stale in_progress bead(s) may overstate live agent load",
            summary.stale_in_progress.len()
        ));
    }

    let plan = match build_swarm_doctor_capacity_plan(&sample) {
        Ok(plan) => plan,
        Err(err) => {
            findings.push(swarm_admission_blocked_finding(
                Severity::Fail,
                "Live swarm admission decision unavailable",
                format!("capacity plan could not be built from live host sample: {err}"),
                &warnings,
            ));
            return;
        }
    };

    let live_load = live_load_from_beads_summary(&summary);
    findings.push(classify_swarm_admission(plan, sample, live_load, &warnings));
}

fn build_swarm_doctor_capacity_plan(
    sample: &HostResourceSample,
) -> std::result::Result<SwarmCapacityPlan, SwarmCapacityPlanError> {
    let budgets = HostResourceBudgets::from_host();
    let cpu_cores = budgets.cpu_cores.max(1);
    let inventory = SwarmHostInventory::new(
        cpu_cores,
        cpu_cores,
        bytes_to_mib_ceil(budgets.max_rss_bytes.saturating_mul(2)).max(1),
    );
    let evidence = SwarmCapacityEvidenceSummary {
        complete_records: 1,
        host_capacity_rows: 1,
        host_capacity_mismatch_rows: 0,
        max_p99_ms: 250,
        max_p999_ms: 1_000,
        max_queue_depth: budgets.max_queue_depth.max(1),
        max_rss_mb: sample.rss_bytes.map_or(256, bytes_to_mib_ceil).max(1),
        max_cpu_pct: 1.0,
    };

    SwarmCapacityPlannerConfig::default().plan_from_summary(evidence, inventory)
}

fn live_load_from_beads_summary(summary: &BeadsLedgerSummary) -> SwarmLiveLoad {
    SwarmLiveLoad::empty()
        .with_active_agents(
            env_u64("PI_DOCTOR_SWARM_ACTIVE_AGENTS")
                .unwrap_or_else(|| usize_to_u64(summary.in_progress)),
        )
        .with_active_tool_calls(env_u64("PI_DOCTOR_SWARM_ACTIVE_TOOL_CALLS").unwrap_or(0))
        .with_extension_hostcall_lanes(
            env_u64("PI_DOCTOR_SWARM_EXTENSION_HOSTCALL_LANES").unwrap_or(0),
        )
        .with_active_rch_jobs(env_u64("PI_DOCTOR_SWARM_ACTIVE_RCH_JOBS").unwrap_or(0))
}

fn classify_swarm_admission(
    plan: SwarmCapacityPlan,
    sample: HostResourceSample,
    live_load: SwarmLiveLoad,
    warnings: &[String],
) -> Finding {
    let mut controller = SwarmAdmissionController::from_plan(plan);
    let queue_depth = u64_to_usize_saturating(live_load.active_tool_calls.saturating_add(1));
    let resource_pressure_ratio =
        resource_pressure_ratio(&sample, &controller.plan().resource_budgets);
    let tail_latency_sample = TailLatencyRegimeSample::new(
        controller.plan().evidence.max_p99_ms,
        controller.plan().evidence.max_p999_ms,
        queue_depth,
        resource_pressure_ratio,
    );
    let request = ResourceRequest::new(ResourceOperationKind::Tool, "doctor.swarm_admission")
        .with_estimated_tool_output_bytes(
            controller
                .plan()
                .resource_budgets
                .max_tool_output_bytes
                .min(MIB_BYTES),
        )
        .with_queue_depth(queue_depth);
    let decision = controller.decide(&request, sample, tail_latency_sample, live_load);
    let next_actions = swarm_admission_next_actions(decision.action, !warnings.is_empty());
    let remediation = next_actions.join("; ");
    let detail = format_swarm_admission_detail(&decision, warnings);
    let data = swarm_admission_data(&decision, warnings, &next_actions);

    match (decision.action, warnings.is_empty()) {
        (AdmissionAction::Admit, true) => {
            Finding::pass(CheckCategory::Swarm, "Live swarm admission decision: admit")
        }
        (AdmissionAction::Admit, false) => Finding::warn(
            CheckCategory::Swarm,
            "Live swarm admission decision degraded: admit",
        ),
        (AdmissionAction::Backpressure, _) => Finding::warn(
            CheckCategory::Swarm,
            "Live swarm admission decision: backpressure",
        ),
        (AdmissionAction::Deny, _) => {
            Finding::fail(CheckCategory::Swarm, "Live swarm admission decision: deny")
        }
    }
    .with_detail(detail)
    .with_remediation(remediation)
    .with_data(data)
}

fn swarm_admission_blocked_finding(
    severity: Severity,
    title: impl Into<String>,
    detail: String,
    warnings: &[String],
) -> Finding {
    let next_actions = vec![
        "Do not launch new swarm work while the admission action is deny".to_string(),
        "Repair or refresh the coordination inputs".to_string(),
        "Rerun `pi doctor --only swarm --format json`".to_string(),
    ];
    let remediation = next_actions.join("; ");
    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_ADMISSION_SCHEMA,
        "source": {
            "capacity_plan": "unavailable",
            "live_load": "unavailable",
            "resource_sample": "unavailable"
        },
        "action": action_label(AdmissionAction::Deny),
        "reason": detail,
        "retry_after_ms": 0,
        "pressure_dimension": capacity_dimension_label(SwarmCapacityDimension::None),
        "capacity_pressure": null,
        "planned_budgets": null,
        "live_counts": null,
        "resource_sample": null,
        "admission_decision": null,
        "stale_data_warnings": warnings,
        "next_actions": next_actions
    });

    match severity {
        Severity::Pass => Finding::pass(CheckCategory::Swarm, title),
        Severity::Info => Finding::info(CheckCategory::Swarm, title),
        Severity::Warn => Finding::warn(CheckCategory::Swarm, title),
        Severity::Fail => Finding::fail(CheckCategory::Swarm, title),
    }
    .with_detail(detail)
    .with_remediation(remediation)
    .with_data(data)
}

fn swarm_admission_data(
    decision: &crate::resource_governor::SwarmAdmissionControllerDecision,
    warnings: &[String],
    next_actions: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "schema": SWARM_DOCTOR_ADMISSION_SCHEMA,
        "source": {
            "capacity_plan": "doctor_live_host_sample",
            "live_load": "beads_ledger_with_env_overrides",
            "resource_sample": "host_resource_sample_current"
        },
        "action": action_label(decision.action),
        "reason": decision.reason,
        "retry_after_ms": decision.retry_after_ms,
        "pressure_dimension": capacity_dimension_label(decision.capacity_pressure.dimension),
        "capacity_pressure": decision.capacity_pressure,
        "planned_budgets": {
            "agent_concurrency": decision.recommended_agent_concurrency,
            "tool_concurrency": decision.recommended_tool_concurrency,
            "extension_hostcall_lanes": decision.recommended_extension_hostcall_lanes,
            "rch_verification_fanout": decision.recommended_rch_verification_fanout,
            "max_queue_depth": decision.resource_decision.budgets.max_queue_depth,
            "max_tool_output_bytes": decision.resource_decision.budgets.max_tool_output_bytes,
            "memory_pressure_threshold_ratio": decision.resource_decision.budgets.backpressure_ratio,
            "deny_ratio": decision.resource_decision.budgets.deny_ratio,
            "plan_confidence": decision.plan_confidence
        },
        "live_counts": decision.live_load,
        "resource_sample": decision.resource_decision.sample,
        "admission_decision": decision.telemetry(),
        "stale_data_warnings": warnings,
        "next_actions": next_actions
    })
}

fn format_swarm_admission_detail(
    decision: &crate::resource_governor::SwarmAdmissionControllerDecision,
    warnings: &[String],
) -> String {
    let pressure = decision.capacity_pressure;
    let mut detail = format!(
        "action={}, reason={}, retry_after_ms={}, pressure={} {}/{} ({:.2}x), live_agents={}, live_tool_calls={}, live_extension_lanes={}, live_rch_jobs={}, planned_agents={}, planned_tool_calls={}, planned_extension_lanes={}, planned_rch_jobs={}",
        action_label(decision.action),
        decision.reason,
        decision.retry_after_ms,
        capacity_dimension_label(pressure.dimension),
        pressure.observed,
        pressure.budget,
        pressure.ratio,
        decision.live_load.active_agents,
        decision.live_load.active_tool_calls,
        decision.live_load.extension_hostcall_lanes,
        decision.live_load.active_rch_jobs,
        decision.recommended_agent_concurrency,
        decision.recommended_tool_concurrency,
        decision.recommended_extension_hostcall_lanes,
        decision.recommended_rch_verification_fanout
    );
    if !warnings.is_empty() {
        detail.push_str("; stale_data_warnings=");
        detail.push_str(&warnings.join("; "));
    }
    detail
}

fn swarm_admission_next_actions(action: AdmissionAction, has_warnings: bool) -> Vec<String> {
    let mut actions = match action {
        AdmissionAction::Admit => vec![
            "Proceed with new swarm work only after current leases are visible".to_string(),
            "Keep CARGO_TARGET_DIR and TMPDIR on high-capacity storage before cargo checks"
                .to_string(),
        ],
        AdmissionAction::Backpressure => vec![
            "Delay new swarm work until the reported retry_after_ms has elapsed".to_string(),
            "Reduce active agents or tool calls on the pressure dimension".to_string(),
            "Rerun `pi doctor --only swarm --format json` before heavyweight cargo checks"
                .to_string(),
        ],
        AdmissionAction::Deny => vec![
            "Do not launch new swarm work while the admission action is deny".to_string(),
            "Stop or defer agents on the pressure dimension".to_string(),
            "Rerun `pi doctor --only swarm --format json` after pressure clears".to_string(),
        ],
    };
    if has_warnings {
        actions.push(
            "Repair stale or missing inputs before treating the decision as healthy".to_string(),
        );
    }
    actions
}

const fn action_label(action: AdmissionAction) -> &'static str {
    match action {
        AdmissionAction::Admit => "admit",
        AdmissionAction::Backpressure => "backpressure",
        AdmissionAction::Deny => "deny",
    }
}

const fn capacity_dimension_label(dimension: SwarmCapacityDimension) -> &'static str {
    match dimension {
        SwarmCapacityDimension::ActiveAgents => "active_agents",
        SwarmCapacityDimension::ActiveToolCalls => "active_tool_calls",
        SwarmCapacityDimension::ExtensionHostcallLanes => "extension_hostcall_lanes",
        SwarmCapacityDimension::RchVerificationFanout => "rch_verification_fanout",
        SwarmCapacityDimension::None => "none",
    }
}

fn resource_sample_warnings(sample: &HostResourceSample) -> Vec<String> {
    let mut warnings = Vec::new();
    if sample.load_avg_1m.is_none() {
        warnings.push("host load average unavailable".to_string());
    }
    if sample.rss_bytes.is_none() {
        warnings.push("process RSS sample unavailable".to_string());
    }
    if sample.process_count.is_none() {
        warnings.push("host process-count sample unavailable".to_string());
    }
    if sample.fd_count.is_none() {
        warnings.push("file-descriptor sample unavailable".to_string());
    }
    warnings
}

#[allow(clippy::cast_precision_loss)]
fn resource_pressure_ratio(sample: &HostResourceSample, budgets: &HostResourceBudgets) -> f64 {
    let mut ratio = 0.0_f64;
    if let Some(load_avg_1m) = sample.load_avg_1m {
        ratio = ratio.max(load_avg_1m / budgets.max_load_avg_1m.max(f64::EPSILON));
    }
    if let Some(rss_bytes) = sample.rss_bytes {
        ratio = ratio.max((rss_bytes as f64) / (budgets.max_rss_bytes.max(1) as f64));
    }
    if let Some(process_count) = sample.process_count {
        ratio = ratio.max((process_count as f64) / (budgets.max_processes.max(1) as f64));
    }
    if let Some(fd_count) = sample.fd_count {
        ratio = ratio.max((fd_count as f64) / (budgets.max_fds.max(1) as f64));
    }
    ratio
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.trim().parse::<u64>().ok()
}

const fn bytes_to_mib_ceil(bytes: u64) -> u64 {
    bytes.saturating_add(MIB_BYTES - 1) / MIB_BYTES
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn u64_to_usize_saturating(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn summarize_beads_ledger(
    content: &str,
    now: DateTime<Utc>,
    stale_after_hours: i64,
) -> BeadsLedgerSummary {
    let mut summary = BeadsLedgerSummary::default();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        summary.total += 1;
        let Ok(issue) = serde_json::from_str::<BeadsIssueRecord>(line) else {
            summary.parse_errors += 1;
            continue;
        };

        match issue.status.as_str() {
            "open" => {
                summary.open += 1;
                summary.active += 1;
            }
            "in_progress" => {
                summary.in_progress += 1;
                summary.active += 1;
                if let Some(stale) = stale_issue_from_record(issue, now, stale_after_hours) {
                    summary.stale_in_progress.push(stale);
                }
            }
            _ => {}
        }
    }
    summary
}

fn stale_issue_from_record(
    issue: BeadsIssueRecord,
    now: DateTime<Utc>,
    stale_after_hours: i64,
) -> Option<StaleIssue> {
    let updated_at = issue.updated_at?;
    let parsed = DateTime::parse_from_rfc3339(&updated_at).ok()?;
    let age_hours = now
        .signed_duration_since(parsed.with_timezone(&Utc))
        .num_hours();
    (age_hours >= stale_after_hours).then_some(StaleIssue {
        id: issue.id,
        title: issue.title,
        updated_at,
        age_hours,
    })
}

fn format_stale_issues(issues: &[StaleIssue]) -> String {
    let mut parts: Vec<String> = issues
        .iter()
        .take(SWARM_DETAIL_LIMIT)
        .map(|issue| {
            let title = truncate_chars(&issue.title, 54);
            format!("{}: {title} ({}h old)", issue.id, issue.age_hours)
        })
        .collect();
    if issues.len() > SWARM_DETAIL_LIMIT {
        parts.push(format!("+{} more", issues.len() - SWARM_DETAIL_LIMIT));
    }
    parts.join("; ")
}

#[derive(Default)]
struct StalledReaperAudit {
    parse_errors: usize,
    in_progress_count: usize,
    recently_updated_count: usize,
    active_agent_count: usize,
    blocked_by_note_count: usize,
    unknown_assignee_count: usize,
    suggestions: Vec<serde_json::Value>,
}

impl StalledReaperAudit {
    fn candidate_count(&self) -> usize {
        self.suggestions
            .iter()
            .filter(|suggestion| {
                suggestion.get("action").and_then(serde_json::Value::as_str)
                    == Some("notify_then_reopen_or_claim")
            })
            .count()
    }

    fn detail(&self, candidate_count: usize) -> String {
        format!(
            "in_progress={}, candidates={candidate_count}, active_agent={}, recently_updated={}, blocked_by_note={}, unknown_assignee={}",
            self.in_progress_count,
            self.active_agent_count,
            self.recently_updated_count,
            self.blocked_by_note_count,
            self.unknown_assignee_count
        )
    }
}

fn classify_stalled_bead_reaper(
    content: &str,
    agent_roster: Option<&serde_json::Value>,
    agent_roster_error: Option<&str>,
    now: DateTime<Utc>,
    stale_after_hours: i64,
) -> Finding {
    let activities =
        agent_roster.map_or_else(HashMap::new, |value| agent_mail_activity_index(value, now));
    let audit = collect_stalled_reaper_audit(content, &activities, now, stale_after_hours);
    let candidate_count = audit.candidate_count();
    let detail = audit.detail(candidate_count);
    let parse_errors = audit.parse_errors;
    let in_progress_count = audit.in_progress_count;
    let recently_updated_count = audit.recently_updated_count;
    let active_agent_count = audit.active_agent_count;
    let blocked_by_note_count = audit.blocked_by_note_count;
    let unknown_assignee_count = audit.unknown_assignee_count;
    let suggestions = audit.suggestions;

    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_STALLED_REAPER_SCHEMA,
        "mode": "audit_only",
        "mutation_performed": false,
        "requires_explicit_operator_command": true,
        "stale_after_hours": stale_after_hours,
        "agent_activity_source": if agent_roster.is_some() { "agent_mail" } else { "unavailable" },
        "agent_activity_error": agent_roster_error,
        "parse_errors": parse_errors,
        "in_progress_count": in_progress_count,
        "candidate_count": candidate_count,
        "active_agent_count": active_agent_count,
        "recently_updated_count": recently_updated_count,
        "blocked_by_note_count": blocked_by_note_count,
        "unknown_assignee_count": unknown_assignee_count,
        "suggestions": suggestions,
    });

    if parse_errors > 0 {
        return Finding::warn(CheckCategory::Swarm, "Stalled bead reaper audit degraded")
            .with_detail(format!("{detail}; parse_errors={parse_errors}"))
            .with_remediation("Run `br doctor --json` before reopening any in_progress bead")
            .with_data(data);
    }
    if candidate_count > 0 {
        return Finding::warn(CheckCategory::Swarm, "Stalled bead reaper found reopen candidates")
            .with_detail(detail)
            .with_remediation(
                "Review notification drafts; only run suggested `br update` commands after confirming ownership is stale",
            )
            .with_data(data);
    }
    Finding::pass(
        CheckCategory::Swarm,
        "Stalled bead reaper found no reopen candidates",
    )
    .with_detail(detail)
    .with_data(data)
}

fn collect_stalled_reaper_audit(
    content: &str,
    activities: &HashMap<String, AgentMailActivity>,
    now: DateTime<Utc>,
    stale_after_hours: i64,
) -> StalledReaperAudit {
    let mut audit = StalledReaperAudit::default();

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(issue) = serde_json::from_str::<BeadsIssueRecord>(line) else {
            audit.parse_errors += 1;
            continue;
        };
        if !matches!(issue.status.as_str(), "in_progress") {
            continue;
        }
        audit.in_progress_count += 1;

        let updated_at = issue.updated_at.as_deref().unwrap_or_default();
        let Some(br_age_hours) = age_hours_since(updated_at, now) else {
            audit.suggestions.push(stalled_reaper_suggestion(
                &issue,
                None,
                None,
                "missing_or_invalid_br_updated_at",
                stale_after_hours,
            ));
            continue;
        };
        if br_age_hours < stale_after_hours {
            audit.recently_updated_count += 1;
            continue;
        }

        if let Some(note_excerpt) = blocked_note_excerpt(&issue) {
            audit.blocked_by_note_count += 1;
            audit.suggestions.push(stalled_reaper_watch_item(
                &issue,
                br_age_hours,
                "blocked_by_note",
                &note_excerpt,
            ));
            continue;
        }

        let assignee = issue_assignee(&issue);
        let activity = assignee.and_then(|name| activities.get(name));
        if activity.is_some_and(|activity| activity.age_hours < stale_after_hours) {
            audit.active_agent_count += 1;
            continue;
        }
        if assignee.is_none() || activity.is_none() {
            audit.unknown_assignee_count += 1;
        }
        audit.suggestions.push(stalled_reaper_suggestion(
            &issue,
            Some(br_age_hours),
            activity,
            "stale_in_progress",
            stale_after_hours,
        ));
    }

    audit
}

fn stalled_reaper_suggestion(
    issue: &BeadsIssueRecord,
    br_age_hours: Option<i64>,
    activity: Option<&AgentMailActivity>,
    reason: &str,
    stale_after_hours: i64,
) -> serde_json::Value {
    let assignee = issue_assignee(issue).map(str::to_string);
    let to = assignee.iter().cloned().collect::<Vec<_>>();
    serde_json::json!({
        "issue_id": issue.id,
        "title": issue.title,
        "assignee": assignee,
        "reason": reason,
        "action": "notify_then_reopen_or_claim",
        "br_updated_at": issue.updated_at.as_deref(),
        "br_age_hours": br_age_hours,
        "agent_mail_last_active_ts": activity.map(|activity| activity.last_active_ts.as_str()),
        "agent_mail_age_hours": activity.map(|activity| activity.age_hours),
        "stale_after_hours": stale_after_hours,
        "suggested_commands": [
            format!("br update {} --status=open", issue.id),
            format!("br update {} --status=in_progress --assignee <agent-name>", issue.id),
        ],
        "notification_draft": {
            "to": to,
            "thread_id": issue.id,
            "subject": format!("[{}] Stalled in-progress audit", issue.id),
            "ack_required": true,
            "body_md": stalled_reaper_draft_body(issue, br_age_hours, activity, stale_after_hours),
        },
    })
}

fn stalled_reaper_watch_item(
    issue: &BeadsIssueRecord,
    br_age_hours: i64,
    reason: &str,
    note_excerpt: &str,
) -> serde_json::Value {
    serde_json::json!({
        "issue_id": issue.id,
        "title": issue.title,
        "assignee": issue_assignee(issue),
        "reason": reason,
        "action": "keep_in_progress_and_review_blocker_note",
        "br_updated_at": issue.updated_at.as_deref(),
        "br_age_hours": br_age_hours,
        "note_excerpt": note_excerpt,
        "suggested_commands": [
            format!("br show {}", issue.id),
        ],
    })
}

fn stalled_reaper_draft_body(
    issue: &BeadsIssueRecord,
    br_age_hours: Option<i64>,
    activity: Option<&AgentMailActivity>,
    stale_after_hours: i64,
) -> String {
    let assignee = issue_assignee(issue).unwrap_or("<unassigned>");
    let br_age = br_age_hours.map_or_else(|| "unknown".to_string(), |age| format!("{age}h"));
    let agent_activity = activity.map_or_else(
        || "no recent Agent Mail activity found".to_string(),
        |activity| format!("last Agent Mail activity {}h ago", activity.age_hours),
    );
    format!(
        "`{}` is still in_progress for `{assignee}`. Beads last update age: {br_age}; {agent_activity}. If this is still owned, please reply or refresh the bead. Otherwise I plan to reopen it after the {stale_after_hours}h stale threshold review.",
        issue.id
    )
}

fn issue_assignee(issue: &BeadsIssueRecord) -> Option<&str> {
    issue
        .assignee
        .as_deref()
        .or(issue.owner.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn age_hours_since(timestamp: &str, now: DateTime<Utc>) -> Option<i64> {
    let parsed = DateTime::parse_from_rfc3339(timestamp).ok()?;
    Some(
        now.signed_duration_since(parsed.with_timezone(&Utc))
            .num_hours(),
    )
}

fn blocked_note_excerpt(issue: &BeadsIssueRecord) -> Option<String> {
    let text = issue.notes.as_deref().unwrap_or(&issue.description).trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    [
        "blocked",
        "blocker",
        "waiting on",
        "do not reset",
        "do not reopen",
        "do not reclaim",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    .then(|| truncate_chars(text, 180))
}

fn agent_mail_activity_index(
    value: &serde_json::Value,
    now: DateTime<Utc>,
) -> HashMap<String, AgentMailActivity> {
    let mut activities = HashMap::new();
    collect_agent_mail_activity_rows(value, now, &mut activities);
    activities
}

fn collect_agent_mail_activity_rows(
    value: &serde_json::Value,
    now: DateTime<Utc>,
    activities: &mut HashMap<String, AgentMailActivity>,
) {
    match value {
        serde_json::Value::Object(map) => {
            let name = map
                .get("name")
                .or_else(|| map.get("agent"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let last_active = [
                "last_active_ts",
                "last_active",
                "last_seen_ts",
                "last_seen",
                "updated_at",
            ]
            .iter()
            .find_map(|key| map.get(*key).and_then(serde_json::Value::as_str));
            if let (Some(name), Some(last_active)) = (name, last_active)
                && let Some(age_hours) = age_hours_since(last_active, now)
            {
                activities.insert(
                    name.to_string(),
                    AgentMailActivity {
                        last_active_ts: last_active.to_string(),
                        age_hours,
                    },
                );
                return;
            }
            for child in map.values() {
                collect_agent_mail_activity_rows(child, now, activities);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_agent_mail_activity_rows(child, now, activities);
            }
        }
        _ => {}
    }
}

fn check_swarm_next_action(cwd: &Path, findings: &mut Vec<Finding>) {
    let mut snapshot = SwarmNextActionSnapshot {
        agent_name: first_non_empty_env(&["AGENT_MAIL_AGENT", "AGENT_NAME"]),
        ..SwarmNextActionSnapshot::default()
    };

    apply_next_action_beads_snapshot(cwd, &mut snapshot);
    apply_next_action_br_ready_snapshot(cwd, &mut snapshot);
    apply_next_action_bv_snapshot(cwd, &mut snapshot);
    apply_next_action_agent_mail_snapshot(cwd, &mut snapshot);

    findings.push(classify_swarm_next_action(&snapshot));
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SwarmNextActionSnapshot {
    agent_name: Option<String>,
    mail_unread: u64,
    mail_urgent: u64,
    mail_ack_required: u64,
    reservations_active: usize,
    reservations_own_active: usize,
    beads_open: usize,
    beads_in_progress: usize,
    beads_parse_errors: usize,
    stale_in_progress: usize,
    current_in_progress: usize,
    open_epic_count: usize,
    ready_ids: Vec<String>,
    bv_highest_impact: Option<String>,
    bv_recommendation_count: usize,
    source_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwarmNextAction {
    AckMail,
    ImplementCurrent,
    UnblockStalledBead,
    ClaimReadyBead,
    CreateFollowupBeads,
    NoWork,
}

impl SwarmNextAction {
    const fn label(self) -> &'static str {
        match self {
            Self::AckMail => "ack_mail",
            Self::ImplementCurrent => "implement_current",
            Self::UnblockStalledBead => "unblock_stalled_bead",
            Self::ClaimReadyBead => "claim_ready_bead",
            Self::CreateFollowupBeads => "create_followup_beads",
            Self::NoWork => "no_work",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::AckMail => {
                "Read and acknowledge urgent or ack-required Agent Mail before taking more work"
            }
            Self::ImplementCurrent => {
                "Continue the current claimed work; keep reservations fresh and avoid unrelated coordination churn"
            }
            Self::UnblockStalledBead => {
                "Inspect stalled in-progress beads and contact owners before reopening or reclaiming any work"
            }
            Self::ClaimReadyBead => {
                "Claim the highest-impact ready bead, reserve the edit surface, and announce the start in Agent Mail"
            }
            Self::CreateFollowupBeads => {
                "Break the open roadmap or epic into concrete ready beads before waiting for more coordination"
            }
            Self::NoWork => {
                "No actionable swarm work is visible; rerun triage after syncing Beads and Agent Mail"
            }
        }
    }

    const fn severity(self) -> Severity {
        match self {
            Self::AckMail | Self::UnblockStalledBead | Self::CreateFollowupBeads => Severity::Warn,
            Self::NoWork => Severity::Info,
            Self::ImplementCurrent | Self::ClaimReadyBead => Severity::Pass,
        }
    }
}

fn classify_swarm_next_action(snapshot: &SwarmNextActionSnapshot) -> Finding {
    let (next_action, reason) = select_swarm_next_action(snapshot);
    let mut severity = next_action.severity();
    if !snapshot.source_errors.is_empty() && matches!(severity, Severity::Pass) {
        severity = Severity::Warn;
    }

    let detail = format!(
        "next_action={}, unread={}, urgent={}, ack_required={}, own_reservations={}, ready={}, open={}, in_progress={}, stale_in_progress={}, current_in_progress={}, open_epics={}, bv_highest_impact={}",
        next_action.label(),
        snapshot.mail_unread,
        snapshot.mail_urgent,
        snapshot.mail_ack_required,
        snapshot.reservations_own_active,
        snapshot.ready_ids.len(),
        snapshot.beads_open,
        snapshot.beads_in_progress,
        snapshot.stale_in_progress,
        snapshot.current_in_progress,
        snapshot.open_epic_count,
        snapshot.bv_highest_impact.as_deref().unwrap_or("none")
    );
    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_NEXT_ACTION_SCHEMA,
        "next_action": next_action.label(),
        "reason": reason,
        "agent_name": snapshot.agent_name,
        "mail": {
            "unread": snapshot.mail_unread,
            "urgent": snapshot.mail_urgent,
            "ack_required": snapshot.mail_ack_required
        },
        "reservations": {
            "active_count": snapshot.reservations_active,
            "own_active_count": snapshot.reservations_own_active
        },
        "beads": {
            "open_count": snapshot.beads_open,
            "in_progress_count": snapshot.beads_in_progress,
            "parse_errors": snapshot.beads_parse_errors,
            "ready_count": snapshot.ready_ids.len(),
            "ready_ids": snapshot.ready_ids,
            "stale_in_progress_count": snapshot.stale_in_progress,
            "current_in_progress_count": snapshot.current_in_progress,
            "open_epic_count": snapshot.open_epic_count
        },
        "bv": {
            "highest_impact": snapshot.bv_highest_impact,
            "recommendation_count": snapshot.bv_recommendation_count
        },
        "source_errors": snapshot.source_errors
    });

    finding_with_severity(
        severity,
        format!(
            "Communication-purgatory next action: {}",
            next_action.label()
        ),
    )
    .with_detail(detail)
    .with_remediation(next_action.remediation())
    .with_data(data)
}

fn select_swarm_next_action(snapshot: &SwarmNextActionSnapshot) -> (SwarmNextAction, String) {
    if snapshot.mail_urgent > 0 || snapshot.mail_ack_required > 0 {
        return (
            SwarmNextAction::AckMail,
            "Agent Mail has urgent or ack-required obligations".to_string(),
        );
    }
    if snapshot.current_in_progress > 0 || snapshot.reservations_own_active > 0 {
        return (
            SwarmNextAction::ImplementCurrent,
            "Current agent already owns in-progress work or active file reservations".to_string(),
        );
    }
    if snapshot.stale_in_progress > 0 {
        return (
            SwarmNextAction::UnblockStalledBead,
            "One or more in-progress beads exceed the stale threshold".to_string(),
        );
    }
    if let Some(first_ready) = snapshot.ready_ids.first() {
        return (
            SwarmNextAction::ClaimReadyBead,
            format!("Ready Beads work is available, starting with {first_ready}"),
        );
    }
    if snapshot.open_epic_count > 0 {
        return (
            SwarmNextAction::CreateFollowupBeads,
            "No ready beads are visible, but open epics or roadmaps need decomposition".to_string(),
        );
    }
    (
        SwarmNextAction::NoWork,
        "No mail obligations, ready beads, current work, stale work, or open epics are visible"
            .to_string(),
    )
}

fn finding_with_severity(severity: Severity, title: impl Into<String>) -> Finding {
    match severity {
        Severity::Pass => Finding::pass(CheckCategory::Swarm, title),
        Severity::Info => Finding::info(CheckCategory::Swarm, title),
        Severity::Warn => Finding::warn(CheckCategory::Swarm, title),
        Severity::Fail => Finding::fail(CheckCategory::Swarm, title),
    }
}

fn apply_next_action_beads_snapshot(cwd: &Path, snapshot: &mut SwarmNextActionSnapshot) {
    let ledger_path = cwd.join(".beads/issues.jsonl");
    match std::fs::read_to_string(&ledger_path) {
        Ok(content) => {
            let summary =
                summarize_beads_ledger(&content, Utc::now(), SWARM_STALE_IN_PROGRESS_HOURS);
            snapshot.beads_open = summary.open;
            snapshot.beads_in_progress = summary.in_progress;
            snapshot.beads_parse_errors = summary.parse_errors;
            snapshot.stale_in_progress = summary.stale_in_progress.len();
            apply_next_action_issue_counts(&content, snapshot);
        }
        Err(err) => snapshot.source_errors.push(format!(
            "beads ledger unavailable at {}: {err}",
            ledger_path.display()
        )),
    }
}

fn apply_next_action_issue_counts(content: &str, snapshot: &mut SwarmNextActionSnapshot) {
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(issue) = serde_json::from_str::<BeadsIssueRecord>(line) else {
            continue;
        };
        if issue.status.eq("open") && issue_is_epic(&issue) {
            snapshot.open_epic_count += 1;
        }
        if issue.status.eq("in_progress")
            && snapshot
                .agent_name
                .as_deref()
                .is_some_and(|agent| issue_assignee(&issue) == Some(agent))
        {
            snapshot.current_in_progress += 1;
        }
    }
}

fn issue_is_epic(issue: &BeadsIssueRecord) -> bool {
    issue
        .issue_type
        .as_deref()
        .is_some_and(|issue_type| issue_type.eq_ignore_ascii_case("epic"))
}

fn apply_next_action_br_ready_snapshot(cwd: &Path, snapshot: &mut SwarmNextActionSnapshot) {
    if which_tool("br").is_none() {
        snapshot
            .source_errors
            .push("br CLI not found for ready-work probe".to_string());
        return;
    }
    match run_probe_json(
        SwarmProbeCommand::Br,
        &["ready", "--json"],
        Some(cwd),
        "br ready",
    ) {
        Ok(value) => {
            snapshot.ready_ids = ready_issue_ids(&value)
                .into_iter()
                .take(SWARM_DETAIL_LIMIT)
                .collect();
        }
        Err(err) => snapshot.source_errors.push(err),
    }
}

fn ready_issue_ids(value: &serde_json::Value) -> Vec<String> {
    let Some(values) = value.as_array().or_else(|| {
        value
            .get("issues")
            .or_else(|| value.get("items"))
            .and_then(serde_json::Value::as_array)
    }) else {
        return Vec::new();
    };

    values
        .iter()
        .filter_map(|item| item.get("id").and_then(serde_json::Value::as_str))
        .map(ToString::to_string)
        .collect()
}

fn apply_next_action_bv_snapshot(cwd: &Path, snapshot: &mut SwarmNextActionSnapshot) {
    if which_tool("bv").is_none() {
        snapshot
            .source_errors
            .push("bv CLI not found for graph recommendation probe".to_string());
        return;
    }
    match run_probe_json(
        SwarmProbeCommand::Bv,
        &["--robot-plan"],
        Some(cwd),
        "bv --robot-plan",
    ) {
        Ok(value) => {
            snapshot.bv_highest_impact = value
                .pointer("/plan/summary/highest_impact")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            snapshot.bv_recommendation_count = bv_plan_item_count(&value);
        }
        Err(err) => snapshot.source_errors.push(err),
    }
}

fn bv_plan_item_count(value: &serde_json::Value) -> usize {
    value
        .pointer("/plan/tracks")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |tracks| {
            tracks
                .iter()
                .map(|track| {
                    track
                        .get("items")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len)
                })
                .sum()
        })
}

fn apply_next_action_agent_mail_snapshot(cwd: &Path, snapshot: &mut SwarmNextActionSnapshot) {
    let Some(agent) = snapshot.agent_name.clone() else {
        snapshot.source_errors.push(
            "AGENT_MAIL_AGENT and AGENT_NAME are unset for Agent Mail next-action probe"
                .to_string(),
        );
        return;
    };
    if which_tool("am").is_none() {
        snapshot
            .source_errors
            .push("Agent Mail CLI not found for next-action probe".to_string());
        return;
    }

    let project = cwd.display().to_string();
    apply_next_action_agent_mail_status(cwd, &project, &agent, snapshot);
    apply_next_action_agent_mail_inbox(cwd, &project, &agent, snapshot);
    apply_next_action_agent_mail_reservations(cwd, &project, &agent, snapshot);
}

fn apply_next_action_agent_mail_status(
    cwd: &Path,
    project: &str,
    agent: &str,
    snapshot: &mut SwarmNextActionSnapshot,
) {
    let args = [
        "robot",
        "status",
        "--format",
        "json",
        "--project",
        project,
        "--agent",
        agent,
    ];
    match run_probe_json(SwarmProbeCommand::Am, &args, Some(cwd), "am robot status") {
        Ok(value) => apply_mail_obligation_counts(&value, snapshot),
        Err(err) => snapshot.source_errors.push(err),
    }
}

fn apply_next_action_agent_mail_inbox(
    cwd: &Path,
    project: &str,
    agent: &str,
    snapshot: &mut SwarmNextActionSnapshot,
) {
    let args = [
        "robot",
        "inbox",
        "--format",
        "json",
        "--project",
        project,
        "--agent",
        agent,
        "--unread",
        "--limit",
        "20",
    ];
    match run_probe_json(SwarmProbeCommand::Am, &args, Some(cwd), "am robot inbox") {
        Ok(value) => apply_mail_obligation_counts(&value, snapshot),
        Err(err) => snapshot.source_errors.push(err),
    }
}

fn apply_next_action_agent_mail_reservations(
    cwd: &Path,
    project: &str,
    agent: &str,
    snapshot: &mut SwarmNextActionSnapshot,
) {
    let args = [
        "robot",
        "reservations",
        "--format",
        "json",
        "--project",
        project,
        "--all",
    ];
    match run_probe_json(
        SwarmProbeCommand::Am,
        &args,
        Some(cwd),
        "am robot reservations",
    ) {
        Ok(value) => {
            let counts = agent_mail_reservation_counts(&value, agent);
            snapshot.reservations_active = counts.active;
            snapshot.reservations_own_active = counts.own_active;
        }
        Err(err) => snapshot.source_errors.push(err),
    }
}

fn apply_mail_obligation_counts(value: &serde_json::Value, snapshot: &mut SwarmNextActionSnapshot) {
    snapshot.mail_unread = snapshot
        .mail_unread
        .max(json_number_by_key(value, "unread").unwrap_or(0));
    snapshot.mail_urgent = snapshot
        .mail_urgent
        .max(json_number_by_key(value, "urgent").unwrap_or(0));
    snapshot.mail_ack_required = snapshot
        .mail_ack_required
        .max(json_number_by_key(value, "ack_required").unwrap_or(0));
    let message_counts = count_mail_message_obligations(value);
    snapshot.mail_urgent = snapshot.mail_urgent.max(message_counts.urgent);
    snapshot.mail_ack_required = snapshot.mail_ack_required.max(message_counts.ack_required);
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MailMessageObligationCounts {
    urgent: u64,
    ack_required: u64,
}

fn count_mail_message_obligations(value: &serde_json::Value) -> MailMessageObligationCounts {
    let mut counts = MailMessageObligationCounts::default();
    count_mail_message_obligations_inner(value, &mut counts);
    counts
}

fn count_mail_message_obligations_inner(
    value: &serde_json::Value,
    counts: &mut MailMessageObligationCounts,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("subject")
                || map.contains_key("message_id")
                || map.contains_key("id")
            {
                if map
                    .get("ack_required")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                {
                    counts.ack_required += 1;
                }
                let importance = map
                    .get("importance")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if matches!(importance, "urgent" | "high") {
                    counts.urgent += 1;
                }
            }
            for child in map.values() {
                count_mail_message_obligations_inner(child, counts);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                count_mail_message_obligations_inner(child, counts);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AgentMailReservationNextActionCounts {
    active: usize,
    own_active: usize,
}

fn agent_mail_reservation_counts(
    value: &serde_json::Value,
    agent: &str,
) -> AgentMailReservationNextActionCounts {
    let mut counts = AgentMailReservationNextActionCounts::default();
    count_agent_mail_reservation_rows(value, agent, &mut counts);
    counts
}

fn count_agent_mail_reservation_rows(
    value: &serde_json::Value,
    agent: &str,
    counts: &mut AgentMailReservationNextActionCounts,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("path") || map.contains_key("path_pattern") {
                let released = map
                    .get("released_ts")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                    || map
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|status| status.eq_ignore_ascii_case("released"));
                if !released {
                    counts.active += 1;
                    let holder = map
                        .get("agent")
                        .or_else(|| map.get("holder"))
                        .or_else(|| map.get("agent_name"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if holder.eq(agent) {
                        counts.own_active += 1;
                    }
                }
                return;
            }
            for child in map.values() {
                count_agent_mail_reservation_rows(child, agent, counts);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                count_agent_mail_reservation_rows(child, agent, counts);
            }
        }
        _ => {}
    }
}

fn run_probe_json(
    command: SwarmProbeCommand,
    args: &[&str],
    cwd: Option<&Path>,
    label: &str,
) -> std::result::Result<serde_json::Value, String> {
    match run_tool_with_timeout(command, args, cwd, SWARM_PROBE_TIMEOUT) {
        Ok(outcome) if outcome.timed_out => Err(format!(
            "{label} timed out after {}s",
            SWARM_PROBE_TIMEOUT.as_secs()
        )),
        Ok(outcome) if !outcome.success => Err(format!(
            "{label} failed: {}",
            command_failure_detail(&outcome)
        )),
        Ok(outcome) => serde_json::from_str::<serde_json::Value>(&outcome.stdout)
            .map_err(|err| format!("{label} returned non-JSON output: {err}")),
        Err(err) => Err(format!("{label} failed to start: {err}")),
    }
}

fn check_swarm_br_status(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    if which_tool("br").is_none() {
        findings.push(
            Finding::warn(cat, "br not found for Beads DB status")
                .with_remediation("Install/repair beads_rust before starting a swarm"),
        );
        return;
    }
    let args = ["sync", "--status", "--json"];
    match run_tool_with_timeout(SwarmProbeCommand::Br, &args, Some(cwd), SWARM_PROBE_TIMEOUT) {
        Ok(outcome) if outcome.timed_out => {
            findings.push(
                Finding::warn(cat, "br sync status timed out").with_remediation(
                    "Run `br doctor --json`; avoid claiming work until Beads responds",
                ),
            );
        }
        Ok(outcome) if outcome.success => {
            match serde_json::from_str::<serde_json::Value>(&outcome.stdout) {
                Ok(value) => findings.push(classify_br_sync_status(&value)),
                Err(err) => findings.push(
                    Finding::warn(cat, "br sync status returned non-JSON output")
                        .with_detail(format!("{err}; {}", redacted_output_snippet(&outcome)))
                        .with_remediation(
                            "Run `br sync --status --json` and `br doctor --json` manually",
                        ),
                ),
            }
        }
        Ok(outcome) => {
            findings.push(
                Finding::fail(cat, "Beads DB/status probe failed")
                    .with_detail(command_failure_detail(&outcome))
                    .with_remediation("Run `br doctor --json` and rebuild from healthy issues.jsonl before claiming more work"),
            );
        }
        Err(err) => {
            findings.push(
                Finding::warn(cat, "br sync status failed to start")
                    .with_detail(err.to_string())
                    .with_remediation("Run `br doctor --json` before claiming more work"),
            );
        }
    }
}

fn classify_br_sync_status(value: &serde_json::Value) -> Finding {
    let dirty_count = json_number_by_key(value, "dirty_count").unwrap_or(0);
    let jsonl_newer = json_bool_by_key(value, "jsonl_newer").unwrap_or(false);
    let db_newer = json_bool_by_key(value, "db_newer").unwrap_or(false);
    let detail =
        format!("dirty_count={dirty_count}, jsonl_newer={jsonl_newer}, db_newer={db_newer}");
    if dirty_count > 0 || jsonl_newer || db_newer {
        Finding::warn(CheckCategory::Swarm, "Beads DB/JSONL sync drift detected")
            .with_detail(detail)
            .with_remediation(
                "Run `br sync --status --json`; coordinate before importing or exporting",
            )
    } else {
        Finding::pass(CheckCategory::Swarm, "Beads DB/JSONL sync status clean").with_detail(detail)
    }
}

fn check_swarm_agent_mail(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    let Some(am_path) = which_tool("am") else {
        findings.push(
            Finding::warn(cat, "Agent Mail CLI not found")
                .with_remediation("Install/repair MCP Agent Mail before running a large swarm"),
        );
        return;
    };

    findings.push(Finding::pass(cat, format!("Agent Mail CLI ({am_path})")));

    let agent_name = first_non_empty_env(&["AGENT_MAIL_AGENT", "AGENT_NAME"]);
    let project = cwd.display().to_string();

    if let Some(agent) = agent_name.as_deref() {
        findings.push(Finding::pass(
            cat,
            format!("Agent Mail agent identity: {agent}"),
        ));
        check_swarm_agent_mail_agent_probes(cwd, project.as_str(), agent, findings);
    } else {
        findings.push(
            Finding::warn(cat, "Agent Mail agent identity not set")
                .with_detail("AGENT_MAIL_AGENT and AGENT_NAME are both unset")
                .with_remediation(
                    "Register with MCP Agent Mail and export AGENT_NAME before claiming swarm work",
                ),
        );
    }

    let reservations_args = [
        "robot",
        "reservations",
        "--format",
        "json",
        "--project",
        project.as_str(),
        "--all",
        "--expiring",
        "30",
    ];
    probe_agent_mail_json(
        SwarmProbeCommand::Am,
        &reservations_args,
        cwd,
        "Agent Mail reservations",
        classify_agent_mail_reservations,
        "Run `am robot reservations --all --format json` and resolve conflicts or renew expiring leases",
        findings,
    );

    check_swarm_agent_mail_build_slots(cwd, agent_name.as_deref(), findings);
}

fn check_swarm_agent_mail_agent_probes(
    cwd: &Path,
    project: &str,
    agent: &str,
    findings: &mut Vec<Finding>,
) {
    let status_args = [
        "robot",
        "status",
        "--format",
        "json",
        "--project",
        project,
        "--agent",
        agent,
    ];
    probe_agent_mail_json(
        SwarmProbeCommand::Am,
        &status_args,
        cwd,
        "Agent Mail status",
        classify_agent_mail_status,
        "Retry after active Agent Mail maintenance finishes; if it stays busy, inspect `am robot health --format json`",
        findings,
    );

    let inbox_args = [
        "robot",
        "inbox",
        "--format",
        "json",
        "--project",
        project,
        "--agent",
        agent,
        "--unread",
        "--limit",
        "20",
    ];
    probe_agent_mail_json(
        SwarmProbeCommand::Am,
        &inbox_args,
        cwd,
        "Agent Mail inbox",
        classify_agent_mail_inbox,
        "Run `am robot inbox --unread --format json` or fetch inbox through MCP before claiming more files",
        findings,
    );

    let contacts_args = [
        "robot",
        "contacts",
        "--format",
        "json",
        "--project",
        project,
        "--agent",
        agent,
    ];
    probe_agent_mail_json(
        SwarmProbeCommand::Am,
        &contacts_args,
        cwd,
        "Agent Mail contacts",
        classify_agent_mail_contacts,
        "Run `am robot contacts --format json` and resolve pending or degraded contact links before relying on coordination mail",
        findings,
    );
}

fn probe_agent_mail_json<F>(
    command: SwarmProbeCommand,
    args: &[&str],
    cwd: &Path,
    label: &str,
    classify: F,
    remediation: &str,
    findings: &mut Vec<Finding>,
) where
    F: FnOnce(&serde_json::Value) -> Finding,
{
    let cat = CheckCategory::Swarm;
    match run_tool_with_timeout(command, args, Some(cwd), SWARM_PROBE_TIMEOUT) {
        Ok(outcome) if outcome.timed_out => {
            findings.push(
                Finding::warn(cat, format!("{label} probe timed out"))
                    .with_detail(format!(
                        "command: am {}; timeout={}s",
                        args.join(" "),
                        SWARM_PROBE_TIMEOUT.as_secs()
                    ))
                    .with_remediation(remediation),
            );
        }
        Ok(outcome) if !outcome.success => {
            findings.push(
                Finding::warn(cat, format!("{label} probe unavailable"))
                    .with_detail(command_failure_detail(&outcome))
                    .with_remediation(remediation),
            );
        }
        Ok(outcome) => match serde_json::from_str::<serde_json::Value>(&outcome.stdout) {
            Ok(value) => findings.push(classify(&value)),
            Err(err) => findings.push(
                Finding::warn(cat, format!("{label} probe returned non-JSON output"))
                    .with_detail(format!("{err}; {}", redacted_output_snippet(&outcome)))
                    .with_remediation(remediation),
            ),
        },
        Err(err) => findings.push(
            Finding::warn(cat, format!("{label} probe failed to start"))
                .with_detail(err.to_string())
                .with_remediation(remediation),
        ),
    }
}

fn classify_agent_mail_status(value: &serde_json::Value) -> Finding {
    let unread = json_number_by_key(value, "unread").unwrap_or(0);
    let urgent = json_number_by_key(value, "urgent").unwrap_or(0);
    let ack_required = json_number_by_key(value, "ack_required").unwrap_or(0);
    let mut finding = if urgent > 0 || ack_required > 0 {
        Finding::warn(CheckCategory::Swarm, "Agent Mail status needs attention")
            .with_remediation("Read urgent or ack-required messages before taking new leases")
    } else {
        Finding::pass(CheckCategory::Swarm, "Agent Mail status reachable")
    };
    finding.detail = Some(format!(
        "unread={unread}, urgent={urgent}, ack_required={ack_required}"
    ));
    finding
}

fn classify_agent_mail_inbox(value: &serde_json::Value) -> Finding {
    let messages = json_array_len_by_key(value, "messages")
        .or_else(|| json_array_len_by_key(value, "items"))
        .unwrap_or_else(|| json_number_by_key_as_usize(value, "unread").unwrap_or(0));
    let urgent = json_number_by_key(value, "urgent").unwrap_or(0);
    if urgent > 0 {
        Finding::warn(
            CheckCategory::Swarm,
            "Agent Mail inbox has urgent unread messages",
        )
        .with_detail(format!("unread_sample={messages}, urgent={urgent}"))
        .with_remediation("Read or acknowledge urgent mail before claiming more files")
    } else {
        Finding::pass(CheckCategory::Swarm, "Agent Mail inbox reachable")
            .with_detail(format!("unread_sample={messages}, urgent={urgent}"))
    }
}

fn classify_agent_mail_reservations(value: &serde_json::Value) -> Finding {
    classify_agent_mail_reservations_at(value, Utc::now())
}

fn classify_agent_mail_reservations_at(value: &serde_json::Value, now: DateTime<Utc>) -> Finding {
    let heatmap = build_agent_mail_reservation_heatmap(value, now);
    let active = json_array_len_by_key(value, "reservations")
        .or_else(|| json_array_len_by_key(value, "items"))
        .unwrap_or_else(|| json_number_by_key_as_usize(value, "active").unwrap_or(heatmap.active));
    let has_conflict = json_truthy_key_contains(value, "conflict") || !heatmap.conflicts.is_empty();
    let expiring = json_number_by_key(value, "expiring")
        .unwrap_or_else(|| usize_to_u64(heatmap.expiring_soon));
    let detail = heatmap.detail(active, expiring);
    let data = heatmap.to_json();

    if has_conflict {
        Finding::warn(
            CheckCategory::Swarm,
            "Agent Mail reservation conflict heatmap has active conflicts",
        )
        .with_detail(detail)
        .with_remediation("Resolve conflicting file reservations before editing overlapping paths")
        .with_data(data)
    } else if !heatmap.stale_recommendations.is_empty() {
        Finding::warn(
            CheckCategory::Swarm,
            "Agent Mail reservation heatmap has stale holder recommendations",
        )
        .with_detail(detail)
        .with_remediation(
            "Contact stale reservation holders and ask them to renew or release before taking overlapping work",
        )
        .with_data(data)
    } else if expiring > 0 {
        Finding::warn(CheckCategory::Swarm, "Agent Mail reservations expire soon")
            .with_detail(detail)
            .with_remediation("Renew active reservations before long-running verification")
            .with_data(data)
    } else {
        Finding::pass(
            CheckCategory::Swarm,
            "Agent Mail reservation conflict heatmap clear",
        )
        .with_detail(detail)
        .with_data(data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentMailReservationRow {
    path_pattern: String,
    agent: String,
    bead: String,
    reason: Option<String>,
    lease_mode: ReservationLeaseMode,
    activity: ReservationActivity,
    expired: bool,
    released: bool,
    expiring_soon: bool,
    age_hours: Option<i64>,
}

impl AgentMailReservationRow {
    const fn is_exclusive(&self) -> bool {
        matches!(self.lease_mode, ReservationLeaseMode::Exclusive)
    }

    const fn is_active(&self) -> bool {
        matches!(self.activity, ReservationActivity::Active)
    }

    const fn is_recent(&self) -> bool {
        matches!(self.activity, ReservationActivity::RecentInactive)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationLeaseMode {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationActivity {
    Active,
    RecentInactive,
    Inactive,
}

#[derive(Debug, Default)]
struct AgentMailReservationHeatmap {
    rows_seen: usize,
    active: usize,
    recent_inactive: usize,
    expired: usize,
    released: usize,
    exclusive_active: usize,
    shared_active: usize,
    expiring_soon: usize,
    path_groups: HashMap<String, ReservationGroupStats>,
    agent_groups: HashMap<String, ReservationGroupStats>,
    bead_groups: HashMap<String, ReservationGroupStats>,
    conflicts: Vec<serde_json::Value>,
    stale_recommendations: Vec<serde_json::Value>,
}

impl AgentMailReservationHeatmap {
    fn detail(&self, active_fallback: usize, expiring_fallback: u64) -> String {
        let active = if self.rows_seen == 0 {
            active_fallback
        } else {
            self.active
        };
        let expiring = if self.rows_seen == 0 {
            expiring_fallback
        } else {
            usize_to_u64(self.expiring_soon).max(expiring_fallback)
        };
        format!(
            "active={}, recent_inactive={}, conflict_groups={}, stale_holder_recommendations={}, expiring_soon={}, top_paths={}",
            active,
            self.recent_inactive,
            self.conflicts.len(),
            self.stale_recommendations.len(),
            expiring,
            self.top_path_summary()
        )
    }

    fn top_path_summary(&self) -> String {
        let mut groups = self.path_groups.values().collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            right
                .conflict_count
                .cmp(&left.conflict_count)
                .then_with(|| right.active_count.cmp(&left.active_count))
                .then_with(|| left.key.cmp(&right.key))
        });
        let parts = groups
            .into_iter()
            .take(SWARM_DETAIL_LIMIT)
            .map(|group| {
                format!(
                    "{} active={} conflicts={}",
                    group.key, group.active_count, group.conflict_count
                )
            })
            .collect::<Vec<_>>();
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join("; ")
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": SWARM_DOCTOR_RESERVATION_HEATMAP_SCHEMA,
            "recent_window_hours": SWARM_RESERVATION_RECENT_HOURS,
            "stale_holder_hours": SWARM_RESERVATION_STALE_HOLDER_HOURS,
            "totals": {
                "rows_seen": self.rows_seen,
                "active_count": self.active,
                "recent_inactive_count": self.recent_inactive,
                "expired_count": self.expired,
                "released_count": self.released,
                "exclusive_active_count": self.exclusive_active,
                "shared_active_count": self.shared_active,
                "expiring_soon_count": self.expiring_soon,
                "conflict_group_count": self.conflicts.len(),
                "stale_holder_recommendation_count": self.stale_recommendations.len()
            },
            "heatmap": {
                "by_path_pattern": reservation_groups_json(&self.path_groups, "path_pattern"),
                "by_agent": reservation_groups_json(&self.agent_groups, "agent"),
                "by_bead": reservation_groups_json(&self.bead_groups, "bead"),
                "conflicts": self.conflicts
            },
            "stale_holder_recommendations": self.stale_recommendations
        })
    }
}

#[derive(Debug, Clone, Default)]
struct ReservationGroupStats {
    key: String,
    active_count: usize,
    recent_inactive_count: usize,
    exclusive_active_count: usize,
    shared_active_count: usize,
    stale_holder_count: usize,
    conflict_count: usize,
    max_age_hours: Option<i64>,
    agents: HashSet<String>,
    beads: HashSet<String>,
}

fn build_agent_mail_reservation_heatmap(
    value: &serde_json::Value,
    now: DateTime<Utc>,
) -> AgentMailReservationHeatmap {
    let rows = agent_mail_reservation_rows(value, now);
    let mut heatmap = AgentMailReservationHeatmap {
        rows_seen: rows.len(),
        ..AgentMailReservationHeatmap::default()
    };

    for row in &rows {
        if row.expired {
            heatmap.expired += 1;
        }
        if row.released {
            heatmap.released += 1;
        }
        if row.expiring_soon {
            heatmap.expiring_soon += 1;
        }
        if row.is_active() {
            heatmap.active += 1;
            if row.is_exclusive() {
                heatmap.exclusive_active += 1;
            } else {
                heatmap.shared_active += 1;
            }
        } else if row.is_recent() {
            heatmap.recent_inactive += 1;
        }
        if row.is_active() || row.is_recent() {
            insert_reservation_group(&mut heatmap.path_groups, &row.path_pattern, row);
            insert_reservation_group(&mut heatmap.agent_groups, &row.agent, row);
            insert_reservation_group(&mut heatmap.bead_groups, &row.bead, row);
        }
        if reservation_stale_reason(row).is_some() {
            heatmap
                .stale_recommendations
                .push(stale_reservation_recommendation(row));
            mark_reservation_stale(&mut heatmap.path_groups, &row.path_pattern);
            mark_reservation_stale(&mut heatmap.agent_groups, &row.agent);
            mark_reservation_stale(&mut heatmap.bead_groups, &row.bead);
        }
    }

    add_reservation_conflicts(&rows, &mut heatmap);
    heatmap
}

fn agent_mail_reservation_rows(
    value: &serde_json::Value,
    now: DateTime<Utc>,
) -> Vec<AgentMailReservationRow> {
    let mut rows = Vec::new();
    collect_agent_mail_reservation_rows(value, now, &mut rows);
    rows
}

fn collect_agent_mail_reservation_rows(
    value: &serde_json::Value,
    now: DateTime<Utc>,
    rows: &mut Vec<AgentMailReservationRow>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(row) = reservation_row_from_map(map, now) {
                rows.push(row);
                return;
            }
            for (key, child) in map {
                if key.to_ascii_lowercase().contains("conflict") {
                    continue;
                }
                collect_agent_mail_reservation_rows(child, now, rows);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_agent_mail_reservation_rows(child, now, rows);
            }
        }
        _ => {}
    }
}

fn reservation_row_from_map(
    map: &serde_json::Map<String, serde_json::Value>,
    now: DateTime<Utc>,
) -> Option<AgentMailReservationRow> {
    let path_pattern = first_string_field(map, &["path_pattern", "pathPattern", "path"])?
        .trim()
        .to_string();
    if path_pattern.is_empty() {
        return None;
    }
    let agent = first_string_field(
        map,
        &["agent", "holder", "agent_name", "holder_agent", "owner"],
    )
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .unwrap_or("<unknown>")
    .to_string();
    let reason = first_string_field(map, &["reason", "note", "description"]).map(str::to_string);
    let bead = reservation_bead(map, reason.as_deref());
    let released_ts = first_string_field(map, &["released_ts", "released_at"]);
    let expires_ts = first_string_field(map, &["expires_ts", "expires_at", "expiration"]);
    let released = released_ts.is_some()
        || first_string_field(map, &["status"]).is_some_and(|status| {
            status.eq_ignore_ascii_case("released") || status.eq_ignore_ascii_case("closed")
        });
    let expires_at = expires_ts.and_then(parse_rfc3339_utc);
    let expired = expires_at.is_some_and(|expires_at| expires_at <= now);
    let active = !released && !expired;
    let terminal_age_hours = released_ts
        .or(expires_ts)
        .and_then(|timestamp| age_hours_since(timestamp, now));
    let activity_age_hours = first_string_field(
        map,
        &[
            "updated_at",
            "updated_ts",
            "renewed_at",
            "last_active_ts",
            "created_at",
            "created_ts",
        ],
    )
    .and_then(|timestamp| age_hours_since(timestamp, now));
    let recent = !active
        && terminal_age_hours
            .is_some_and(|age| (0..=SWARM_RESERVATION_RECENT_HOURS).contains(&age));
    let expiring_soon = active
        && expires_at.is_some_and(|expires_at| {
            let minutes = expires_at.signed_duration_since(now).num_minutes();
            (0..=SWARM_RESERVATION_EXPIRING_SOON_MINUTES).contains(&minutes)
        });

    Some(AgentMailReservationRow {
        path_pattern,
        agent,
        bead,
        reason,
        lease_mode: reservation_lease_mode(map),
        activity: if active {
            ReservationActivity::Active
        } else if recent {
            ReservationActivity::RecentInactive
        } else {
            ReservationActivity::Inactive
        },
        expired,
        released,
        expiring_soon,
        age_hours: if active {
            activity_age_hours
        } else {
            terminal_age_hours.or(activity_age_hours)
        },
    })
}

fn first_string_field<'a>(
    map: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(serde_json::Value::as_str))
}

fn reservation_lease_mode(
    map: &serde_json::Map<String, serde_json::Value>,
) -> ReservationLeaseMode {
    if let Some(exclusive) = map.get("exclusive").and_then(serde_json::Value::as_bool) {
        return if exclusive {
            ReservationLeaseMode::Exclusive
        } else {
            ReservationLeaseMode::Shared
        };
    }
    if first_string_field(map, &["mode", "kind", "reservation_type", "type"]).is_some_and(|mode| {
        matches!(
            mode.to_ascii_lowercase().as_str(),
            "shared" | "non_exclusive" | "non-exclusive" | "observe" | "read"
        )
    }) {
        ReservationLeaseMode::Shared
    } else {
        ReservationLeaseMode::Exclusive
    }
}

fn reservation_bead(
    map: &serde_json::Map<String, serde_json::Value>,
    reason: Option<&str>,
) -> String {
    first_string_field(map, &["bead", "bead_id", "issue_id", "thread_id"])
        .or_else(|| reason.and_then(extract_bead_id))
        .unwrap_or("<untracked>")
        .to_string()
}

fn extract_bead_id(text: &str) -> Option<&str> {
    text.split_whitespace().find_map(|token| {
        let trimmed = token.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_'))
        });
        trimmed.starts_with("bd-").then_some(trimmed)
    })
}

fn insert_reservation_group(
    groups: &mut HashMap<String, ReservationGroupStats>,
    key: &str,
    row: &AgentMailReservationRow,
) {
    let stats = groups
        .entry(key.to_string())
        .or_insert_with(|| ReservationGroupStats {
            key: key.to_string(),
            ..ReservationGroupStats::default()
        });
    if row.is_active() {
        stats.active_count += 1;
        if row.is_exclusive() {
            stats.exclusive_active_count += 1;
        } else {
            stats.shared_active_count += 1;
        }
    } else if row.is_recent() {
        stats.recent_inactive_count += 1;
    }
    if let Some(age_hours) = row.age_hours {
        stats.max_age_hours = Some(
            stats
                .max_age_hours
                .map_or(age_hours, |current| current.max(age_hours)),
        );
    }
    stats.agents.insert(row.agent.clone());
    stats.beads.insert(row.bead.clone());
}

fn mark_reservation_stale(groups: &mut HashMap<String, ReservationGroupStats>, key: &str) {
    if let Some(stats) = groups.get_mut(key) {
        stats.stale_holder_count += 1;
    }
}

fn add_reservation_conflicts(
    rows: &[AgentMailReservationRow],
    heatmap: &mut AgentMailReservationHeatmap,
) {
    let active_rows = rows
        .iter()
        .filter(|row| row.is_active())
        .collect::<Vec<_>>();
    for (index, left) in active_rows.iter().enumerate() {
        for right in active_rows.iter().skip(index + 1) {
            if !reservation_rows_conflict(left, right) {
                continue;
            }
            mark_reservation_conflict(&mut heatmap.path_groups, &left.path_pattern);
            mark_reservation_conflict(&mut heatmap.path_groups, &right.path_pattern);
            mark_reservation_conflict(&mut heatmap.agent_groups, &left.agent);
            mark_reservation_conflict(&mut heatmap.agent_groups, &right.agent);
            mark_reservation_conflict(&mut heatmap.bead_groups, &left.bead);
            mark_reservation_conflict(&mut heatmap.bead_groups, &right.bead);
            heatmap
                .conflicts
                .push(reservation_conflict_json(left, right));
        }
    }
    heatmap
        .conflicts
        .sort_by_key(std::string::ToString::to_string);
}

fn reservation_rows_conflict(
    left: &AgentMailReservationRow,
    right: &AgentMailReservationRow,
) -> bool {
    reservation_patterns_overlap(&left.path_pattern, &right.path_pattern)
        && (left.is_exclusive() || right.is_exclusive())
        && reservation_agents_distinct(&left.agent, &right.agent)
}

fn reservation_agents_distinct(left: &str, right: &str) -> bool {
    left != right || left == "<unknown>" || right == "<unknown>"
}

fn reservation_patterns_overlap(left: &str, right: &str) -> bool {
    left == right || simple_glob_match(left, right) || simple_glob_match(right, left)
}

fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star_index = None;
    let mut star_text_index = 0;

    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == text[text_index])
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_text_index = text_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_text_index += 1;
            text_index = star_text_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn mark_reservation_conflict(groups: &mut HashMap<String, ReservationGroupStats>, key: &str) {
    if let Some(stats) = groups.get_mut(key) {
        stats.conflict_count += 1;
    }
}

fn reservation_conflict_json(
    left: &AgentMailReservationRow,
    right: &AgentMailReservationRow,
) -> serde_json::Value {
    serde_json::json!({
        "path_patterns": sorted_pair(&left.path_pattern, &right.path_pattern),
        "agents": sorted_pair(&left.agent, &right.agent),
        "beads": sorted_pair(&left.bead, &right.bead),
        "exclusive_involved": left.is_exclusive() || right.is_exclusive(),
        "max_age_hours": max_option_i64(left.age_hours, right.age_hours),
        "reason": "overlapping_active_reservations",
        "recommendation": "Coordinate with holders before editing overlapping files"
    })
}

const fn reservation_stale_reason(row: &AgentMailReservationRow) -> Option<&'static str> {
    if !row.is_active() || !row.is_exclusive() {
        return None;
    }
    match row.age_hours {
        Some(age) if age >= SWARM_RESERVATION_STALE_HOLDER_HOURS => {
            Some("active_exclusive_reservation_older_than_threshold")
        }
        _ => None,
    }
}

fn stale_reservation_recommendation(row: &AgentMailReservationRow) -> serde_json::Value {
    serde_json::json!({
        "agent": row.agent,
        "path_pattern": row.path_pattern,
        "bead": row.bead,
        "reason": reservation_stale_reason(row),
        "age_hours": row.age_hours,
        "reservation_reason": row.reason,
        "suggested_action": "Contact holder and ask them to renew or release before taking overlapping work"
    })
}

fn reservation_groups_json(
    groups: &HashMap<String, ReservationGroupStats>,
    key_name: &str,
) -> Vec<serde_json::Value> {
    let mut values = groups.values().collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .conflict_count
            .cmp(&left.conflict_count)
            .then_with(|| right.active_count.cmp(&left.active_count))
            .then_with(|| left.key.cmp(&right.key))
    });
    values
        .into_iter()
        .map(|stats| reservation_group_json(stats, key_name))
        .collect()
}

fn reservation_group_json(stats: &ReservationGroupStats, key_name: &str) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(key_name.to_string(), serde_json::json!(stats.key));
    object.insert(
        "active_count".to_string(),
        serde_json::json!(stats.active_count),
    );
    object.insert(
        "recent_inactive_count".to_string(),
        serde_json::json!(stats.recent_inactive_count),
    );
    object.insert(
        "exclusive_active_count".to_string(),
        serde_json::json!(stats.exclusive_active_count),
    );
    object.insert(
        "shared_active_count".to_string(),
        serde_json::json!(stats.shared_active_count),
    );
    object.insert(
        "stale_holder_count".to_string(),
        serde_json::json!(stats.stale_holder_count),
    );
    object.insert(
        "conflict_count".to_string(),
        serde_json::json!(stats.conflict_count),
    );
    object.insert(
        "max_age_hours".to_string(),
        serde_json::json!(stats.max_age_hours),
    );
    object.insert(
        "agents".to_string(),
        serde_json::json!(sorted_set(&stats.agents)),
    );
    object.insert(
        "beads".to_string(),
        serde_json::json!(sorted_set(&stats.beads)),
    );
    serde_json::Value::Object(object)
}

fn sorted_set(values: &HashSet<String>) -> Vec<String> {
    let mut values = values.iter().cloned().collect::<Vec<_>>();
    values.sort();
    values
}

fn sorted_pair<'a>(left: &'a str, right: &'a str) -> Vec<&'a str> {
    if left <= right {
        vec![left, right]
    } else {
        vec![right, left]
    }
}

fn max_option_i64(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Debug, Default)]
struct AgentMailContactCounts {
    total: usize,
    pending: usize,
    approved: usize,
    blocked: usize,
    degraded: usize,
    unknown_status: usize,
}

fn classify_agent_mail_contacts(value: &serde_json::Value) -> Finding {
    let mut counts = AgentMailContactCounts::default();
    count_agent_mail_contact_rows(value, &mut counts);
    let detail = format!(
        "contacts={}, pending={}, approved={}, blocked={}, degraded={}, unknown_status={}",
        counts.total,
        counts.pending,
        counts.approved,
        counts.blocked,
        counts.degraded,
        counts.unknown_status
    );
    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_CONTACTS_SCHEMA,
        "contact_count": counts.total,
        "pending_count": counts.pending,
        "approved_count": counts.approved,
        "blocked_count": counts.blocked,
        "degraded_count": counts.degraded,
        "unknown_status_count": counts.unknown_status,
    });

    if counts.pending > 0 {
        return Finding::warn(CheckCategory::Swarm, "Agent Mail contact requests pending")
            .with_detail(detail)
            .with_remediation(
                "Run `am robot contacts --format json` and approve, deny, or refresh pending contact requests before relying on contact-gated mail",
            )
            .with_data(data);
    }
    if counts.degraded > 0 {
        return Finding::warn(CheckCategory::Swarm, "Agent Mail contact graph has degraded rows")
            .with_detail(detail)
            .with_remediation(
                "Inspect Agent Mail contact links for unknown agents, unknown policies, or unrecognized statuses before depending on contact-gated routing",
            )
            .with_data(data);
    }

    Finding::pass(CheckCategory::Swarm, "Agent Mail contacts reachable")
        .with_detail(detail)
        .with_data(data)
}

fn count_agent_mail_contact_rows(value: &serde_json::Value, counts: &mut AgentMailContactCounts) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("from") && map.contains_key("to") && map.contains_key("status") {
                classify_agent_mail_contact_row(map, counts);
                return;
            }
            for child in map.values() {
                count_agent_mail_contact_rows(child, counts);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                count_agent_mail_contact_rows(child, counts);
            }
        }
        _ => {}
    }
}

fn classify_agent_mail_contact_row(
    row: &serde_json::Map<String, serde_json::Value>,
    counts: &mut AgentMailContactCounts,
) {
    counts.total += 1;

    let status = row
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let from = row
        .get("from")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    let to = row
        .get("to")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim();
    let policy = row
        .get("policy")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let recognized_status = match status.as_str() {
        "pending" | "requested" => {
            counts.pending += 1;
            true
        }
        "approved" | "accepted" => {
            counts.approved += 1;
            true
        }
        "blocked" | "denied" | "rejected" => {
            counts.blocked += 1;
            true
        }
        _ => {
            counts.unknown_status += 1;
            false
        }
    };

    let unknown_agent = [from, to]
        .iter()
        .any(|agent| agent.is_empty() || agent.starts_with("[unknown-agent-"));
    let unknown_policy = policy.is_empty() || policy == "unknown";
    if unknown_agent || unknown_policy || !recognized_status {
        counts.degraded += 1;
    }
}

fn check_swarm_agent_mail_build_slots(
    cwd: &Path,
    agent_name: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let Some(agent) = agent_name else {
        findings.push(agent_mail_build_slots_unavailable_finding(
            "AGENT_MAIL_AGENT and AGENT_NAME are both unset",
        ));
        return;
    };

    let project = cwd.display().to_string();
    let args = ["amctl", "env", "-p", project.as_str(), "-a", agent];
    match run_tool_with_timeout(SwarmProbeCommand::Am, &args, Some(cwd), SWARM_PROBE_TIMEOUT) {
        Ok(outcome) if outcome.timed_out => {
            findings.push(agent_mail_build_slots_unavailable_finding(
                "am amctl env timed out before reporting archive paths",
            ));
        }
        Ok(outcome) if !outcome.success => {
            findings.push(
                agent_mail_build_slots_unavailable_finding(
                    "am amctl env did not report archive paths",
                )
                .with_detail(command_failure_detail(&outcome)),
            );
        }
        Ok(outcome) => {
            if let Some(project_archive) = parse_agent_mail_project_archive(&outcome.stdout) {
                let archive = read_agent_mail_build_slot_archive(&project_archive);
                findings.push(classify_agent_mail_build_slots(
                    &archive.values,
                    archive.read_errors,
                    Utc::now(),
                ));
            } else {
                findings.push(
                    agent_mail_build_slots_unavailable_finding(
                        "am amctl env output did not include ARTIFACT_DIR",
                    )
                    .with_detail(redacted_output_snippet(&outcome)),
                );
            }
        }
        Err(err) => {
            findings.push(
                agent_mail_build_slots_unavailable_finding("am amctl env failed to start")
                    .with_detail(err.to_string()),
            );
        }
    }
}

#[derive(Debug, Default)]
struct AgentMailBuildSlotArchive {
    values: Vec<serde_json::Value>,
    read_errors: usize,
}

fn read_agent_mail_build_slot_archive(project_archive: &Path) -> AgentMailBuildSlotArchive {
    let build_slots_dir = project_archive.join("build_slots");
    if !build_slots_dir.exists() {
        return AgentMailBuildSlotArchive::default();
    }

    let mut archive = AgentMailBuildSlotArchive::default();
    let Ok(slot_dirs) = std::fs::read_dir(&build_slots_dir) else {
        archive.read_errors += 1;
        return archive;
    };

    for slot_dir in slot_dirs {
        let Ok(slot_dir) = slot_dir else {
            archive.read_errors += 1;
            continue;
        };
        let Ok(file_type) = slot_dir.file_type() else {
            archive.read_errors += 1;
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        read_agent_mail_build_slot_dir(&slot_dir.path(), &mut archive);
    }

    archive
}

fn read_agent_mail_build_slot_dir(path: &Path, archive: &mut AgentMailBuildSlotArchive) {
    let Ok(entries) = std::fs::read_dir(path) else {
        archive.read_errors += 1;
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            archive.read_errors += 1;
            continue;
        };
        let path = entry.path();
        if !matches!(path.extension().and_then(|ext| ext.to_str()), Some("json")) {
            continue;
        }
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        {
            Some(value) => archive.values.push(value),
            None => archive.read_errors += 1,
        }
    }
}

fn parse_agent_mail_project_archive(env_output: &str) -> Option<PathBuf> {
    env_output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        if key != "ARTIFACT_DIR" {
            return None;
        }
        let artifact_dir = PathBuf::from(trim_matching_shell_quotes(value.trim()));
        artifact_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    })
}

fn trim_matching_shell_quotes(value: &str) -> &str {
    value
        .strip_prefix('\'')
        .and_then(|stripped| stripped.strip_suffix('\''))
        .or_else(|| {
            value
                .strip_prefix('"')
                .and_then(|stripped| stripped.strip_suffix('"'))
        })
        .unwrap_or(value)
}

#[derive(Debug, Default)]
struct AgentMailBuildSlotCounts {
    total: usize,
    active: usize,
    active_shared: usize,
    active_exclusive: usize,
    soon_expiring: usize,
    stale: usize,
    released: usize,
    malformed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AgentMailBuildSlotSummary {
    slot: String,
    agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch: Option<String>,
    exclusive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    acquired_ts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_ts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    released_ts: Option<String>,
    classification: String,
}

fn classify_agent_mail_build_slots(
    values: &[serde_json::Value],
    read_errors: usize,
    now: DateTime<Utc>,
) -> Finding {
    let mut counts = AgentMailBuildSlotCounts {
        malformed: read_errors,
        ..AgentMailBuildSlotCounts::default()
    };
    let mut summaries = values
        .iter()
        .map(|value| summarize_agent_mail_build_slot(value, now, &mut counts))
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        build_slot_classification_rank(&left.classification)
            .cmp(&build_slot_classification_rank(&right.classification))
            .then_with(|| left.slot.cmp(&right.slot))
            .then_with(|| left.agent.cmp(&right.agent))
            .then_with(|| left.branch.cmp(&right.branch))
    });

    let visible_slots = summaries
        .iter()
        .take(SWARM_DETAIL_LIMIT)
        .collect::<Vec<_>>();
    let truncated_slot_count = summaries.len().saturating_sub(visible_slots.len());
    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_BUILD_SLOT_SCHEMA,
        "source": "agent_mail_archive_build_slots",
        "source_supported": true,
        "soon_expiring_minutes": SWARM_BUILD_SLOT_SOON_EXPIRING_MINUTES,
        "total_count": counts.total,
        "active_count": counts.active,
        "active_shared_count": counts.active_shared,
        "active_exclusive_count": counts.active_exclusive,
        "soon_expiring_count": counts.soon_expiring,
        "stale_count": counts.stale,
        "released_count": counts.released,
        "malformed_count": counts.malformed,
        "read_error_count": read_errors,
        "truncated_slot_count": truncated_slot_count,
        "slots": visible_slots
    });
    agent_mail_build_slot_finding(&counts, data)
}

fn summarize_agent_mail_build_slot(
    value: &serde_json::Value,
    now: DateTime<Utc>,
    counts: &mut AgentMailBuildSlotCounts,
) -> AgentMailBuildSlotSummary {
    counts.total += 1;

    let slot = json_string_field(value, "slot");
    let agent = json_string_field(value, "agent");
    let branch = json_string_field(value, "branch");
    let acquired_ts = json_string_field(value, "acquired_ts");
    let expires_ts = json_string_field(value, "expires_ts");
    let released_ts = json_string_field(value, "released_ts");
    let exclusive = value
        .get("exclusive")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let classification = build_slot_classification(
        slot.as_deref(),
        agent.as_deref(),
        expires_ts.as_deref(),
        released_ts.as_deref(),
        now,
    );
    count_build_slot_classification(&classification, exclusive, counts);

    AgentMailBuildSlotSummary {
        slot: slot.unwrap_or_else(|| "unknown".to_string()),
        agent: agent.unwrap_or_else(|| "unknown".to_string()),
        branch,
        exclusive,
        acquired_ts,
        expires_ts,
        released_ts,
        classification,
    }
}

fn build_slot_classification(
    slot: Option<&str>,
    agent: Option<&str>,
    expires_ts: Option<&str>,
    released_ts: Option<&str>,
    now: DateTime<Utc>,
) -> String {
    if released_ts.is_some() {
        return "released".to_string();
    }

    let Some(expires_at) = expires_ts.and_then(parse_rfc3339_utc) else {
        return "malformed".to_string();
    };
    if slot.is_none() || agent.is_none() {
        return "malformed".to_string();
    }
    if expires_at <= now {
        return "stale_expired".to_string();
    }
    let seconds_until_expiry = (expires_at - now).num_seconds();
    if seconds_until_expiry <= SWARM_BUILD_SLOT_SOON_EXPIRING_MINUTES * 60 {
        return "soon_expiring".to_string();
    }
    "active".to_string()
}

fn count_build_slot_classification(
    classification: &str,
    exclusive: bool,
    counts: &mut AgentMailBuildSlotCounts,
) {
    match classification {
        "active" | "soon_expiring" => {
            counts.active += 1;
            if exclusive {
                counts.active_exclusive += 1;
            } else {
                counts.active_shared += 1;
            }
            if classification == "soon_expiring" {
                counts.soon_expiring += 1;
            }
        }
        "stale_expired" => counts.stale += 1,
        "released" => counts.released += 1,
        _ => counts.malformed += 1,
    }
}

fn agent_mail_build_slot_finding(
    counts: &AgentMailBuildSlotCounts,
    data: serde_json::Value,
) -> Finding {
    let detail = format!(
        "active={}, shared={}, exclusive={}, soon_expiring={}, stale={}, malformed={}",
        counts.active,
        counts.active_shared,
        counts.active_exclusive,
        counts.soon_expiring,
        counts.stale,
        counts.malformed
    );

    if counts.malformed > 0 {
        return Finding::warn(
            CheckCategory::Swarm,
            "Agent Mail build-slot records malformed",
        )
        .with_detail(detail)
        .with_remediation(
            "Inspect Agent Mail build_slots archive records before relying on slot posture",
        )
        .with_data(data);
    }
    if counts.active_exclusive > 0 {
        return Finding::warn(CheckCategory::Swarm, "Agent Mail exclusive build slots active")
            .with_detail(detail)
            .with_remediation(
                "Wait for exclusive build-slot holders to finish or coordinate before launching heavyweight cargo/RCH work",
            )
            .with_data(data);
    }
    if counts.soon_expiring > 0 {
        return Finding::warn(CheckCategory::Swarm, "Agent Mail build slots expire soon")
            .with_detail(detail)
            .with_remediation("Renew build-slot leases before long-running cargo/RCH work")
            .with_data(data);
    }
    if counts.active > 0 {
        return Finding::info(CheckCategory::Swarm, "Agent Mail shared build slots active")
            .with_detail(detail)
            .with_data(data);
    }
    if counts.stale > 0 {
        return Finding::info(
            CheckCategory::Swarm,
            "Agent Mail stale build-slot records present",
        )
        .with_detail(detail)
        .with_data(data);
    }
    Finding::pass(CheckCategory::Swarm, "Agent Mail build slots clear")
        .with_detail(detail)
        .with_data(data)
}

fn agent_mail_build_slots_unavailable_finding(reason: &str) -> Finding {
    Finding::info(CheckCategory::Swarm, "Agent Mail build slots unavailable")
        .with_detail(reason)
        .with_data(serde_json::json!({
            "schema": SWARM_DOCTOR_BUILD_SLOT_SCHEMA,
            "source": "agent_mail_archive_build_slots",
            "source_supported": false,
            "reason": reason
        }))
}

fn build_slot_classification_rank(classification: &str) -> u8 {
    match classification {
        "malformed" => 0,
        "active" => 1,
        "soon_expiring" => 2,
        "stale_expired" => 3,
        "released" => 4,
        _ => 5,
    }
}

fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate_chars(value, 120))
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn check_swarm_git(cwd: &Path, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    if which_tool("git").is_none() {
        findings.push(
            Finding::warn(cat, "git not found for swarm dirty-state check")
                .with_remediation("Install git or run the dirty-state check manually"),
        );
        return;
    }
    let args = ["status", "--porcelain=v1", "--untracked-files=all"];
    match run_tool_with_timeout(
        SwarmProbeCommand::Git,
        &args,
        Some(cwd),
        SWARM_PROBE_TIMEOUT,
    ) {
        Ok(outcome) if outcome.timed_out => {
            findings.push(
                Finding::warn(cat, "git status timed out")
                    .with_remediation("Run `git status --short` before staging or committing"),
            );
        }
        Ok(outcome) if outcome.success => {
            let summary = summarize_git_porcelain(&outcome.stdout);
            if summary.total.eq(&0) {
                findings.push(Finding::pass(cat, "Git working tree clean"));
            } else {
                findings.push(
                    Finding::warn(cat, "Git working tree has uncommitted changes")
                        .with_detail(format!(
                            "{} total ({} staged, {} unstaged, {} untracked, {} deleted)",
                            summary.total,
                            summary.staged,
                            summary.unstaged,
                            summary.untracked,
                            summary.deleted
                        ))
                        .with_remediation(
                            "Run `git status --short` and avoid overwriting other agents' files",
                        ),
                );
            }
        }
        Ok(outcome) => {
            findings.push(
                Finding::warn(cat, "git status failed")
                    .with_detail(command_failure_detail(&outcome))
                    .with_remediation("Run `git status --short` manually before staging"),
            );
        }
        Err(err) => {
            findings.push(
                Finding::warn(cat, "git status failed to start")
                    .with_detail(err.to_string())
                    .with_remediation("Run `git status --short` manually before staging"),
            );
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GitPorcelainSummary {
    staged: usize,
    unstaged: usize,
    untracked: usize,
    deleted: usize,
    total: usize,
}

fn summarize_git_porcelain(output: &str) -> GitPorcelainSummary {
    let mut summary = GitPorcelainSummary::default();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        summary.total += 1;
        let bytes = line.as_bytes();
        let x = bytes.first().copied().unwrap_or(b' ');
        let y = bytes.get(1).copied().unwrap_or(b' ');
        if x.eq(&b'?') && y.eq(&b'?') {
            summary.untracked += 1;
            continue;
        }
        if x.ne(&b' ') {
            summary.staged += 1;
        }
        if y.ne(&b' ') {
            summary.unstaged += 1;
        }
        if x.eq(&b'D') || y.eq(&b'D') {
            summary.deleted += 1;
        }
    }
    summary
}

fn check_swarm_rch(findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    if which_tool("rch").is_none() {
        findings.push(
            Finding::warn(cat, "rch not found").with_remediation(
                "Install/repair rch before running heavyweight swarm verification",
            ),
        );
        return;
    }
    match run_tool_with_timeout(
        SwarmProbeCommand::Rch,
        &["status"],
        None,
        SWARM_PROBE_TIMEOUT,
    ) {
        Ok(outcome) if outcome.timed_out => {
            findings.push(Finding::warn(cat, "rch status timed out").with_remediation(
                "Run `rch status` or defer heavyweight cargo checks until workers respond",
            ));
        }
        Ok(outcome) if outcome.success => {
            findings.push(
                Finding::pass(cat, "rch status reachable")
                    .with_detail(redacted_output_snippet(&outcome)),
            );
        }
        Ok(outcome) => findings.push(rch_failure_finding(&outcome)),
        Err(err) => {
            findings.push(
                Finding::warn(cat, "rch status failed to start")
                    .with_detail(err.to_string())
                    .with_remediation("Run `rch doctor` and use a high-capacity local target dir if rch is unavailable"),
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RchFailureKind {
    ArtifactRetrievalDiskPressure,
    LocalTargetDiskPressure,
    RemoteBuildOrTestFailure,
    Unknown,
}

impl RchFailureKind {
    const fn label(self) -> &'static str {
        match self {
            Self::ArtifactRetrievalDiskPressure => "artifact_retrieval_disk_pressure",
            Self::LocalTargetDiskPressure => "local_target_tmpdir_disk_pressure",
            Self::RemoteBuildOrTestFailure => "remote_build_or_test_failure",
            Self::Unknown => "unknown_rch_failure",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::ArtifactRetrievalDiskPressure => {
                "rch artifact retrieval failed after remote success"
            }
            Self::LocalTargetDiskPressure => "rch local target/TMPDIR disk pressure",
            Self::RemoteBuildOrTestFailure => "rch remote build/test failure",
            Self::Unknown => "rch status failed",
        }
    }

    const fn code_regression(self) -> Option<bool> {
        match self {
            Self::ArtifactRetrievalDiskPressure | Self::LocalTargetDiskPressure => Some(false),
            Self::RemoteBuildOrTestFailure => Some(true),
            Self::Unknown => None,
        }
    }

    const fn fail_closed(self) -> bool {
        matches!(self, Self::Unknown)
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::ArtifactRetrievalDiskPressure => {
                "Remote execution appears to have completed; rerun with CARGO_TARGET_DIR and TMPDIR under /data/tmp/pi_agent_rust_cargo/<agent>/ so artifact retrieval has local headroom"
            }
            Self::LocalTargetDiskPressure => {
                "Export CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/<agent>/target and TMPDIR=/data/tmp/pi_agent_rust_cargo/<agent>/tmp, create both dirs, then rerun the RCH command"
            }
            Self::RemoteBuildOrTestFailure => {
                "Treat this as a real compile/test failure; inspect the cargo error and fix the code or test before rerunning"
            }
            Self::Unknown => {
                "Run `rch doctor`, keep the raw RCH status visible, and do not classify this as disk pressure or a code regression until the failure signature is understood"
            }
        }
    }
}

fn rch_failure_finding(outcome: &CommandOutcome) -> Finding {
    let kind = classify_rch_failure(outcome);
    let detail = command_failure_detail(outcome);
    let code_regression = kind.code_regression();
    let data = serde_json::json!({
        "schema": SWARM_DOCTOR_RCH_FAILURE_SCHEMA,
        "classification": kind.label(),
        "code_regression": code_regression,
        "fail_closed": kind.fail_closed(),
        "raw_status": {
            "exit_code": outcome.status_code,
            "timed_out": outcome.timed_out,
            "success": outcome.success
        },
        "evidence": redacted_output_snippet(outcome),
        "remediation": kind.remediation()
    });

    Finding::warn(CheckCategory::Swarm, kind.title())
        .with_detail(detail)
        .with_remediation(kind.remediation())
        .with_data(data)
}

fn classify_rch_failure(outcome: &CommandOutcome) -> RchFailureKind {
    let text = rch_failure_text(outcome);
    let has_disk_pressure = contains_any(
        &text,
        &[
            "no space left on device",
            "enospc",
            "disk quota exceeded",
            "not enough space",
        ],
    );
    let mentions_retrieval = contains_any(
        &text,
        &[
            "artifact retrieval",
            "retrieve artifact",
            "retrieving artifact",
            "download artifact",
            "fetch artifact",
            "copy artifact",
            "sync artifact",
            "failed to retrieve",
            "failed to download",
            "failed to copy",
            "failed to sync",
        ],
    );
    let remote_succeeded = contains_any(
        &text,
        &[
            "remote command succeeded",
            "remote build succeeded",
            "remote build completed",
            "remote execution succeeded",
            "build completed successfully",
            "completed successfully",
            "exit status 0",
        ],
    );

    if mentions_retrieval && (has_disk_pressure || remote_succeeded) {
        return RchFailureKind::ArtifactRetrievalDiskPressure;
    }

    if has_disk_pressure
        && contains_any(
            &text,
            &[
                "cargo_target_dir",
                "tmpdir",
                "target/debug",
                "target/release",
                "/target/",
                "target dir",
                "temporary directory",
                "temp dir",
            ],
        )
    {
        return RchFailureKind::LocalTargetDiskPressure;
    }

    if contains_any(
        &text,
        &[
            "could not compile",
            "compilation failed",
            "cargo check failed",
            "cargo clippy failed",
            "cargo test failed",
            "test result: failed",
            "error[",
            "error:",
        ],
    ) {
        return RchFailureKind::RemoteBuildOrTestFailure;
    }

    RchFailureKind::Unknown
}

fn rch_failure_text(outcome: &CommandOutcome) -> String {
    format!("{}\n{}", outcome.stdout, outcome.stderr).to_ascii_lowercase()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn check_swarm_temp_dirs(findings: &mut Vec<Finding>) {
    check_swarm_temp_dir("CARGO_TARGET_DIR", findings);
    check_swarm_temp_dir("TMPDIR", findings);
}

fn check_swarm_temp_dir(env_name: &str, findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Swarm;
    let Some(raw_path) = std::env::var_os(env_name) else {
        findings.push(
            Finding::warn(cat, format!("{env_name} is not set"))
                .with_detail(format!(
                    "Heavyweight swarm checks should use {SWARM_CARGO_SCRATCH_ROOT}/<agent>"
                ))
                .with_remediation(format!(
                    "Export CARGO_TARGET_DIR and TMPDIR under {SWARM_CARGO_SCRATCH_ROOT}/<agent>/ before cargo checks"
                ))
                .with_data(swarm_temp_dir_data(env_name, None, false, None)),
        );
        return;
    };
    let path = PathBuf::from(raw_path);
    if !path.is_dir() {
        findings.push(
            Finding::warn(cat, format!("{env_name} does not point to a directory"))
                .with_detail(path.display().to_string())
                .with_remediation(format!(
                    "Create {} or export {env_name} to an existing high-capacity directory",
                    path.display()
                ))
                .with_data(swarm_temp_dir_data(env_name, Some(&path), false, None)),
        );
        return;
    }

    match disk_available_kb(&path) {
        Ok(available_kb) => {
            findings.push(swarm_temp_dir_finding(env_name, &path, available_kb, None));
        }
        Err(err) => {
            let detail = err.to_string();
            findings.push(swarm_temp_dir_finding(
                env_name,
                &path,
                None,
                Some(detail.as_str()),
            ));
        }
    }
}

fn swarm_temp_dir_finding(
    env_name: &str,
    path: &Path,
    available_kb: Option<u64>,
    probe_error: Option<&str>,
) -> Finding {
    let cat = CheckCategory::Swarm;
    let data = swarm_temp_dir_data(env_name, Some(path), true, available_kb);

    if let Some(available_kb) = available_kb {
        if available_kb < SWARM_DISK_WARN_AVAILABLE_KB {
            return Finding::warn(cat, format!("{env_name} has low free space"))
                .with_detail(format!(
                    "{} available at {}",
                    format_available_kb(available_kb),
                    path.display()
                ))
                .with_remediation("Switch to a larger /data/tmp target or wait for cleanup before heavy cargo checks")
                .with_data(data);
        }
    }

    if !path_under_swarm_scratch_root(path) {
        let detail = available_kb.map_or_else(
            || {
                format!(
                    "{}; expected path under {SWARM_CARGO_SCRATCH_ROOT}",
                    path.display()
                )
            },
            |available_kb| {
                format!(
                    "{} available at {}; expected path under {SWARM_CARGO_SCRATCH_ROOT}",
                    format_available_kb(available_kb),
                    path.display()
                )
            },
        );
        return Finding::warn(cat, format!("{env_name} is outside swarm scratch root"))
            .with_detail(detail)
            .with_remediation(format!(
                "Export {env_name} under {SWARM_CARGO_SCRATCH_ROOT}/<agent>/ before heavyweight RCH or cargo checks"
            ))
            .with_data(data);
    }

    if let Some(available_kb) = available_kb {
        return Finding::pass(cat, format!("{env_name} headroom"))
            .with_detail(format!(
                "{} available at {}",
                format_available_kb(available_kb),
                path.display()
            ))
            .with_data(data);
    }

    if let Some(error) = probe_error {
        return Finding::info(cat, format!("{env_name} headroom probe failed"))
            .with_detail(error.to_string())
            .with_remediation("Run `df -h` on the configured path before heavy cargo checks")
            .with_data(data);
    }

    Finding::info(cat, format!("{env_name} headroom unavailable"))
        .with_detail(path.display().to_string())
        .with_remediation("Run `df -h` on the configured path before heavy cargo checks")
        .with_data(data)
}

fn swarm_temp_dir_data(
    env_name: &str,
    path: Option<&Path>,
    exists: bool,
    available_kb: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": SWARM_DOCTOR_TEMP_DIR_SCHEMA,
        "env_name": env_name,
        "path": path.map(|p| p.display().to_string()),
        "exists": exists,
        "expected_root": SWARM_CARGO_SCRATCH_ROOT,
        "under_expected_root": path.map(path_under_swarm_scratch_root),
        "available_kb": available_kb,
        "warn_available_kb": SWARM_DISK_WARN_AVAILABLE_KB,
        "recommended_pattern": format!("{SWARM_CARGO_SCRATCH_ROOT}/<agent>/target or {SWARM_CARGO_SCRATCH_ROOT}/<agent>/tmp"),
    })
}

fn path_under_swarm_scratch_root(path: &Path) -> bool {
    path.starts_with(Path::new(SWARM_CARGO_SCRATCH_ROOT))
}

fn disk_available_kb(path: &Path) -> std::io::Result<Option<u64>> {
    if which_tool("df").is_none() {
        return Ok(None);
    }
    let path_arg = path.display().to_string();
    let outcome = run_tool_with_timeout(
        SwarmProbeCommand::Df,
        &["-Pk", path_arg.as_str()],
        None,
        SWARM_PROBE_TIMEOUT,
    )?;
    if outcome.success {
        Ok(parse_df_available_kb(&outcome.stdout))
    } else {
        Ok(None)
    }
}

fn parse_df_available_kb(output: &str) -> Option<u64> {
    output
        .lines()
        .skip(1)
        .find_map(|line| line.split_whitespace().nth(3)?.parse::<u64>().ok())
}

fn format_available_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        let tenths = kb.saturating_mul(10) / (1024 * 1024);
        format!("{}.{:01} GiB", tenths / 10, tenths % 10)
    } else {
        let tenths = kb.saturating_mul(10) / 1024;
        format!("{}.{:01} MiB", tenths / 10, tenths % 10)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandOutcome {
    timed_out: bool,
    success: bool,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwarmProbeCommand {
    Am,
    Br,
    Bv,
    Df,
    Git,
    Rch,
}

fn run_tool_with_timeout(
    tool: SwarmProbeCommand,
    args: &[&str],
    cwd: Option<&Path>,
    timeout: Duration,
) -> std::io::Result<CommandOutcome> {
    let mut command = match tool {
        SwarmProbeCommand::Am => Command::new("am"),
        SwarmProbeCommand::Br => Command::new("br"),
        SwarmProbeCommand::Bv => Command::new("bv"),
        SwarmProbeCommand::Df => Command::new("df"),
        SwarmProbeCommand::Git => Command::new("git"),
        SwarmProbeCommand::Rch => Command::new("rch"),
    };
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }

    let mut child = command.spawn()?;
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }

    let output = child.wait_with_output()?;
    Ok(CommandOutcome {
        timed_out,
        success: output.status.success(),
        status_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn command_failure_detail(outcome: &CommandOutcome) -> String {
    format!(
        "exit={:?}; {}",
        outcome.status_code,
        redacted_output_snippet(outcome)
    )
}

fn redacted_output_snippet(outcome: &CommandOutcome) -> String {
    let stdout = redact_sensitive_lines(outcome.stdout.trim(), 3);
    if !stdout.is_empty() {
        return stdout;
    }
    let stderr = redact_sensitive_lines(outcome.stderr.trim(), 3);
    if !stderr.is_empty() {
        return stderr;
    }
    "no output".to_string()
}

fn redact_sensitive_lines(text: &str, max_lines: usize) -> String {
    text.lines()
        .take(max_lines)
        .map(|line| {
            if line_is_sensitive(line) {
                "[redacted sensitive output line]".to_string()
            } else {
                truncate_chars(line.trim(), 220)
            }
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn line_is_sensitive(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn first_non_empty_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn json_number_by_key(value: &serde_json::Value, key: &str) -> Option<u64> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(found) = map.get(key).and_then(json_value_as_u64) {
                return Some(found);
            }
            map.values()
                .find_map(|child| json_number_by_key(child, key))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|child| json_number_by_key(child, key)),
        _ => None,
    }
}

fn json_number_by_key_as_usize(value: &serde_json::Value, key: &str) -> Option<usize> {
    json_number_by_key(value, key).and_then(|number| usize::try_from(number).ok())
}

fn json_array_len_by_key(value: &serde_json::Value, key: &str) -> Option<usize> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(values)) = map.get(key) {
                return Some(values.len());
            }
            map.values()
                .find_map(|child| json_array_len_by_key(child, key))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|child| json_array_len_by_key(child, key)),
        _ => None,
    }
}

fn json_bool_by_key(value: &serde_json::Value, key: &str) -> Option<bool> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Bool(found)) = map.get(key) {
                return Some(*found);
            }
            map.values().find_map(|child| json_bool_by_key(child, key))
        }
        serde_json::Value::Array(values) => {
            values.iter().find_map(|child| json_bool_by_key(child, key))
        }
        _ => None,
    }
}

fn json_truthy_key_contains(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, child)| {
            (key.to_ascii_lowercase().contains(needle) && json_value_is_truthy(child))
                || json_truthy_key_contains(child, needle)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|child| json_truthy_key_contains(child, needle)),
        _ => false,
    }
}

fn json_value_as_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::Array(values) => Some(values.len() as u64),
        _ => None,
    }
}

fn json_value_is_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => number.as_u64().is_some_and(|value| value > 0),
        serde_json::Value::String(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty()
                && normalized.ne("0")
                && normalized.ne("false")
                && normalized.ne("none")
        }
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
        serde_json::Value::Null => false,
    }
}

// ── Check: Sessions ─────────────────────────────────────────────────

fn check_sessions(findings: &mut Vec<Finding>) {
    let cat = CheckCategory::Sessions;
    let sessions_dir = Config::sessions_dir();

    if !sessions_dir.is_dir() {
        findings.push(Finding::info(
            cat,
            "Sessions directory does not exist (no sessions yet)",
        ));
        return;
    }

    let entries = walk_sessions(&sessions_dir);
    let total = entries.len().min(500); // Cap scan
    let mut corrupt = 0u32;

    for entry in entries.into_iter().take(500) {
        let Ok(path) = entry else {
            corrupt += 1;
            continue;
        };
        if !is_session_healthy(&path) {
            corrupt += 1;
        }
    }

    if corrupt.eq(&0) {
        findings.push(Finding::pass(cat, format!("{total} sessions, 0 corrupt")));
    } else {
        findings.push(
            Finding::warn(cat, format!("{total} sessions, {corrupt} corrupt"))
                .with_detail("Some session files are empty or have invalid headers")
                .with_remediation("Corrupt sessions can be safely deleted"),
        );
    }
}

/// Quick health check: non-empty and first line parses as a valid session header.
fn is_session_healthy(path: &Path) -> bool {
    #[cfg(feature = "sqlite-sessions")]
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq("sqlite"))
    {
        return futures::executor::block_on(async {
            crate::session_sqlite::load_session_meta(path)
                .await
                .is_ok_and(|meta| meta.header.is_valid())
        });
    }

    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => false, // empty or unreadable
        Ok(_) => serde_json::from_str::<SessionHeader>(&line).is_ok_and(|header| header.is_valid()),
    }
}

// ── Check: Extension ────────────────────────────────────────────────

fn check_extension(
    cwd: &Path,
    path: &str,
    policy_override: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    use crate::extension_preflight::{FindingSeverity, PreflightAnalyzer, PreflightVerdict};

    let cat = CheckCategory::Extensions;
    let ext_path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };

    if !ext_path.exists() {
        findings.push(
            Finding::fail(
                cat,
                format!("Extension path not found: {}", ext_path.display()),
            )
            .with_remediation("Check the path and try again"),
        );
        return;
    }

    let config_path = Config::config_path_override_from_env(cwd);
    let resolved = match Config::load_with_roots(config_path.as_deref(), &Config::global_dir(), cwd)
    {
        Ok(config) => config.resolve_extension_policy_with_metadata(policy_override),
        Err(err) => {
            findings.push(
                Finding::fail(
                    cat,
                    "Failed to load configuration for extension policy resolution",
                )
                .with_detail(err.to_string())
                .with_remediation(
                    "Fix the malformed settings.json, point PI_CONFIG_PATH at a valid file, or rerun with `--policy <safe|balanced|permissive>` to inspect extension compatibility independently",
                ),
            );
            let has_explicit_policy =
                policy_override.is_some() || std::env::var_os("PI_EXTENSION_POLICY").is_some();
            if has_explicit_policy {
                Config::default().resolve_extension_policy_with_metadata(policy_override)
            } else {
                // If project config is unreadable, fail closed instead of silently
                // analyzing under the default permissive profile.
                Config::default().resolve_extension_policy_with_metadata(Some("safe"))
            }
        }
    };
    let ext_id = ext_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let analyzer = PreflightAnalyzer::new(&resolved.policy, Some(ext_id));
    let report = analyzer.analyze(&ext_path);

    // Convert preflight verdict to a top-level finding
    match report.verdict {
        PreflightVerdict::Pass => {
            findings.push(Finding::pass(
                cat,
                format!("Extension {ext_id}: compatible"),
            ));
        }
        PreflightVerdict::Warn => {
            findings.push(
                Finding::warn(cat, format!("Extension {ext_id}: partial compatibility"))
                    .with_detail(format!(
                        "{} warning(s), {} info",
                        report.summary.warnings, report.summary.info
                    )),
            );
        }
        PreflightVerdict::Fail => {
            findings.push(
                Finding::fail(cat, format!("Extension {ext_id}: incompatible"))
                    .with_detail(format!(
                        "{} error(s), {} warning(s)",
                        report.summary.errors, report.summary.warnings
                    ))
                    .with_remediation(format!("Try: pi doctor {path} --policy permissive")),
            );
        }
    }

    // Convert individual preflight findings
    for pf in &report.findings {
        let severity = match pf.severity {
            FindingSeverity::Error => Severity::Fail,
            FindingSeverity::Warning => Severity::Warn,
            FindingSeverity::Info => Severity::Info,
        };
        let mut f = Finding {
            category: cat,
            severity,
            title: pf.message.clone(),
            detail: pf.file.as_ref().map(|file| {
                pf.line
                    .map_or_else(|| format!("at {file}"), |line| format!("at {file}:{line}"))
            }),
            remediation: pf.remediation.clone(),
            data: None,
            fixability: Fixability::NotFixable,
        };
        // Ensure we don't lose location info
        if f.detail.is_none() && pf.file.is_some() {
            f.detail.clone_from(&pf.file);
        }
        findings.push(f);
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn write_extension_fixture(cwd: &Path, source: &str) -> PathBuf {
        let extension_dir = cwd.join("ext");
        std::fs::create_dir_all(&extension_dir).expect("create extension dir");
        std::fs::write(extension_dir.join("index.js"), source).expect("write extension source");
        extension_dir
    }

    fn test_swarm_capacity_plan() -> SwarmCapacityPlan {
        let evidence = SwarmCapacityEvidenceSummary {
            complete_records: 5,
            host_capacity_rows: 5,
            host_capacity_mismatch_rows: 0,
            max_p99_ms: 100,
            max_p999_ms: 300,
            max_queue_depth: 16,
            max_rss_mb: 256,
            max_cpu_pct: 40.0,
        };
        SwarmCapacityPlannerConfig::default()
            .plan_from_summary(evidence, SwarmHostInventory::new(8, 8, 32_768))
            .expect("test capacity plan")
    }

    fn healthy_resource_sample() -> HostResourceSample {
        HostResourceSample {
            load_avg_1m: Some(1.0),
            rss_bytes: Some(128 * MIB_BYTES),
            process_count: Some(16),
            fd_count: Some(64),
        }
    }

    fn finding_data(finding: &Finding) -> &serde_json::Value {
        finding.data.as_ref().expect("structured finding data")
    }

    fn build_slot_test_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-09T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn heatmap_test_now() -> DateTime<Utc> {
        build_slot_test_now()
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Pass < Severity::Info);
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Fail);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Pass.to_string(), "PASS");
        assert_eq!(Severity::Fail.to_string(), "FAIL");
    }

    #[test]
    fn check_category_parse() {
        assert_eq!(
            "config".parse::<CheckCategory>().unwrap(),
            CheckCategory::Config
        );
        assert_eq!(
            "dirs".parse::<CheckCategory>().unwrap(),
            CheckCategory::Dirs
        );
        assert_eq!(
            "directories".parse::<CheckCategory>().unwrap(),
            CheckCategory::Dirs
        );
        assert_eq!(
            "auth".parse::<CheckCategory>().unwrap(),
            CheckCategory::Auth
        );
        assert_eq!(
            "shell".parse::<CheckCategory>().unwrap(),
            CheckCategory::Shell
        );
        assert_eq!(
            "sessions".parse::<CheckCategory>().unwrap(),
            CheckCategory::Sessions
        );
        assert_eq!(
            "swarm".parse::<CheckCategory>().unwrap(),
            CheckCategory::Swarm
        );
        assert_eq!(
            "coordination".parse::<CheckCategory>().unwrap(),
            CheckCategory::Swarm
        );
        assert_eq!(
            "leases".parse::<CheckCategory>().unwrap(),
            CheckCategory::Swarm
        );
        assert_eq!(
            "extensions".parse::<CheckCategory>().unwrap(),
            CheckCategory::Extensions
        );
        assert_eq!(
            "ext".parse::<CheckCategory>().unwrap(),
            CheckCategory::Extensions
        );
        assert!("unknown".parse::<CheckCategory>().is_err());
    }

    #[test]
    fn finding_builders() {
        let f = Finding::pass(CheckCategory::Config, "test")
            .with_detail("detail")
            .with_remediation("fix it");
        assert_eq!(f.severity, Severity::Pass);
        assert_eq!(f.detail.as_deref(), Some("detail"));
        assert_eq!(f.remediation.as_deref(), Some("fix it"));

        let f = Finding::warn(CheckCategory::Auth, "warn test").auto_fixable();
        assert_eq!(f.fixability, Fixability::AutoFixable);

        let f = Finding::fail(CheckCategory::Dirs, "fail test").fixed();
        assert_eq!(f.severity, Severity::Pass); // fixed downgrades to pass
        assert_eq!(f.fixability, Fixability::Fixed);
    }

    #[test]
    fn report_summary() {
        let findings = vec![
            Finding::pass(CheckCategory::Config, "ok"),
            Finding::info(CheckCategory::Auth, "info"),
            Finding::warn(CheckCategory::Shell, "warn"),
            Finding::fail(CheckCategory::Dirs, "fail"),
        ];
        let report = DoctorReport::from_findings(findings);
        assert_eq!(report.summary.pass, 1);
        assert_eq!(report.summary.info, 1);
        assert_eq!(report.summary.warn, 1);
        assert_eq!(report.summary.fail, 1);
        assert_eq!(report.overall, Severity::Fail);
    }

    #[test]
    fn report_all_pass() {
        let findings = vec![
            Finding::pass(CheckCategory::Config, "a"),
            Finding::pass(CheckCategory::Dirs, "b"),
        ];
        let report = DoctorReport::from_findings(findings);
        assert_eq!(report.overall, Severity::Pass);
    }

    #[test]
    fn render_text_includes_header() {
        let report =
            DoctorReport::from_findings(vec![Finding::pass(CheckCategory::Config, "all good")]);
        let text = report.render_text();
        assert!(text.contains("Pi Doctor"));
        assert!(text.contains("[PASS] Configuration"));
        assert!(text.contains("[PASS] all good"));
    }

    #[test]
    fn render_text_includes_swarm_category() {
        let report =
            DoctorReport::from_findings(vec![Finding::pass(CheckCategory::Swarm, "ready")]);
        let text = report.render_text();
        assert!(text.contains("[PASS] Swarm Coordination"));
        assert!(text.contains("[PASS] ready"));
    }

    #[test]
    fn render_json_valid() {
        let report = DoctorReport::from_findings(vec![Finding::pass(CheckCategory::Config, "ok")]);
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("findings").is_some());
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("overall").is_some());
    }

    #[test]
    fn render_markdown_includes_header() {
        let report =
            DoctorReport::from_findings(vec![Finding::warn(CheckCategory::Auth, "expired")]);
        let md = report.render_markdown();
        assert!(md.contains("# Pi Doctor Report"));
        assert!(md.contains("## Authentication"));
    }

    #[test]
    fn known_config_keys_includes_common() {
        assert!(is_known_config_key("theme"));
        assert!(is_known_config_key("defaultModel"));
        assert!(is_known_config_key("extensionPolicy"));
        assert!(!is_known_config_key("nonexistent_key_xyz"));
    }

    #[test]
    fn swarm_beads_summary_detects_stale_in_progress() {
        let now = DateTime::parse_from_rfc3339("2026-05-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let content = r#"{"id":"bd-old","title":"Old owner","status":"in_progress","updated_at":"2026-05-07T11:00:00Z"}
{"id":"bd-fresh","title":"Fresh owner","status":"in_progress","updated_at":"2026-05-08T11:30:00Z"}
{"id":"bd-open","title":"Open work","status":"open","updated_at":"2026-05-08T10:00:00Z"}
"#;

        let summary = summarize_beads_ledger(content, now, 24);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.active, 3);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.in_progress, 2);
        assert_eq!(summary.parse_errors, 0);
        assert_eq!(summary.stale_in_progress.len(), 1);
        assert_eq!(summary.stale_in_progress[0].id.as_str(), "bd-old");
    }

    #[test]
    fn swarm_beads_summary_counts_parse_errors() {
        let now = DateTime::parse_from_rfc3339("2026-05-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let content = r#"{"id":"bd-open","title":"Open work","status":"open","updated_at":"2026-05-08T10:00:00Z"}
not-json
"#;

        let summary = summarize_beads_ledger(content, now, 24);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.parse_errors, 1);
    }

    #[test]
    fn stalled_bead_reaper_keeps_recent_and_active_work() {
        let now = DateTime::parse_from_rfc3339("2026-05-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let content = r#"{"id":"bd-active","title":"Active owner","status":"in_progress","assignee":"ActiveAgent","updated_at":"2026-05-08T06:00:00Z"}
{"id":"bd-recent","title":"Recent work","status":"in_progress","assignee":"QuietAgent","updated_at":"2026-05-09T11:00:00Z"}
"#;
        let roster = serde_json::json!({
            "agents": [
                {"name": "ActiveAgent", "last_active_ts": "2026-05-09T11:30:00Z"},
                {"name": "QuietAgent", "last_active_ts": "2026-05-08T00:00:00Z"}
            ]
        });

        let finding = classify_stalled_bead_reaper(content, Some(&roster), None, now, 24);

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["candidate_count"], serde_json::json!(0));
        assert_eq!(data["active_agent_count"], serde_json::json!(1));
        assert_eq!(data["recently_updated_count"], serde_json::json!(1));
        assert_eq!(data["mutation_performed"], serde_json::json!(false));
    }

    #[test]
    fn stalled_bead_reaper_keeps_blocked_notes_as_review_items() {
        let now = DateTime::parse_from_rfc3339("2026-05-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let content = r#"{"id":"bd-blocked","title":"Blocked work","status":"in_progress","assignee":"OldAgent","notes":"Blocked by bd-prereq; do not reopen until evidence lands.","updated_at":"2026-05-07T00:00:00Z"}
"#;
        let roster = serde_json::json!({
            "agents": [
                {"name": "OldAgent", "last_active_ts": "2026-05-07T00:00:00Z"}
            ]
        });

        let finding = classify_stalled_bead_reaper(content, Some(&roster), None, now, 24);

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["candidate_count"], serde_json::json!(0));
        assert_eq!(data["blocked_by_note_count"], serde_json::json!(1));
        assert_eq!(
            data["suggestions"][0]["action"],
            serde_json::json!("keep_in_progress_and_review_blocker_note")
        );
    }

    #[test]
    fn stalled_bead_reaper_suggests_reopen_for_truly_stalled_work() {
        let now = DateTime::parse_from_rfc3339("2026-05-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let content = r#"{"id":"bd-stalled","title":"Quiet work","status":"in_progress","assignee":"OldAgent","updated_at":"2026-05-07T00:00:00Z"}
"#;
        let roster = serde_json::json!({
            "agents": [
                {"name": "OldAgent", "last_active_ts": "2026-05-07T00:00:00Z"}
            ]
        });

        let finding = classify_stalled_bead_reaper(content, Some(&roster), None, now, 24);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("reopen candidates"));
        let data = finding_data(&finding);
        assert_eq!(data["schema"], SWARM_DOCTOR_STALLED_REAPER_SCHEMA);
        assert_eq!(data["mode"], serde_json::json!("audit_only"));
        assert_eq!(data["candidate_count"], serde_json::json!(1));
        assert_eq!(
            data["suggestions"][0]["suggested_commands"][0],
            serde_json::json!("br update bd-stalled --status=open")
        );
        assert_eq!(
            data["suggestions"][0]["notification_draft"]["to"][0],
            serde_json::json!("OldAgent")
        );
    }

    #[test]
    fn swarm_next_action_prioritizes_ack_required_mail() {
        let snapshot = SwarmNextActionSnapshot {
            mail_unread: 2,
            mail_ack_required: 1,
            ready_ids: vec!["bd-ready".to_string()],
            ..SwarmNextActionSnapshot::default()
        };

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(data["schema"], SWARM_DOCTOR_NEXT_ACTION_SCHEMA);
        assert_eq!(data["next_action"], serde_json::json!("ack_mail"));
        assert_eq!(data["mail"]["ack_required"], serde_json::json!(1));
    }

    #[test]
    fn swarm_next_action_keeps_current_work_moving() {
        let snapshot = SwarmNextActionSnapshot {
            agent_name: Some("SunnyBeacon".to_string()),
            reservations_active: 1,
            reservations_own_active: 1,
            current_in_progress: 1,
            ready_ids: vec!["bd-ready".to_string()],
            ..SwarmNextActionSnapshot::default()
        };

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["next_action"], serde_json::json!("implement_current"));
        assert_eq!(
            data["reservations"]["own_active_count"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn swarm_next_action_reports_stale_bead_unblock() {
        let snapshot = SwarmNextActionSnapshot {
            stale_in_progress: 1,
            beads_in_progress: 1,
            ready_ids: vec!["bd-ready".to_string()],
            ..SwarmNextActionSnapshot::default()
        };

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(
            data["next_action"],
            serde_json::json!("unblock_stalled_bead")
        );
        assert_eq!(
            data["beads"]["stale_in_progress_count"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn swarm_next_action_claims_ready_work() {
        let snapshot = SwarmNextActionSnapshot {
            ready_ids: vec!["bd-ready".to_string()],
            bv_highest_impact: Some("bd-ready".to_string()),
            bv_recommendation_count: 1,
            ..SwarmNextActionSnapshot::default()
        };

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["next_action"], serde_json::json!("claim_ready_bead"));
        assert_eq!(data["beads"]["ready_ids"][0], serde_json::json!("bd-ready"));
    }

    #[test]
    fn swarm_next_action_decomposes_open_epic_when_ready_queue_empty() {
        let snapshot = SwarmNextActionSnapshot {
            beads_open: 1,
            open_epic_count: 1,
            ..SwarmNextActionSnapshot::default()
        };

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(
            data["next_action"],
            serde_json::json!("create_followup_beads")
        );
        assert_eq!(data["beads"]["ready_count"], serde_json::json!(0));
    }

    #[test]
    fn swarm_next_action_reports_no_work_when_everything_is_empty() {
        let snapshot = SwarmNextActionSnapshot::default();

        let finding = classify_swarm_next_action(&snapshot);

        assert_eq!(finding.severity, Severity::Info);
        let data = finding_data(&finding);
        assert_eq!(data["next_action"], serde_json::json!("no_work"));
        assert_eq!(data["source_errors"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn swarm_admission_reports_healthy_decision_data() {
        let finding = classify_swarm_admission(
            test_swarm_capacity_plan(),
            healthy_resource_sample(),
            SwarmLiveLoad::empty()
                .with_active_agents(1)
                .with_active_tool_calls(1),
            &[],
        );

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["schema"], SWARM_DOCTOR_ADMISSION_SCHEMA);
        assert_eq!(data["action"], "admit");
        assert_eq!(data["pressure_dimension"], "active_agents");
        assert_eq!(data["live_counts"]["active_agents"], serde_json::json!(1));
        assert_eq!(
            data["planned_budgets"]["agent_concurrency"],
            serde_json::json!(4)
        );
        assert!(data["admission_decision"].is_object());
    }

    #[test]
    fn swarm_admission_reports_backpressure_guidance() {
        let finding = classify_swarm_admission(
            test_swarm_capacity_plan(),
            healthy_resource_sample(),
            SwarmLiveLoad::empty().with_active_agents(3),
            &[],
        );

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(data["action"], "backpressure");
        assert_eq!(data["pressure_dimension"], "active_agents");
        assert!(data["retry_after_ms"].as_u64().unwrap_or(0) > 0);
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("Delay new swarm work")
        );
    }

    #[test]
    fn swarm_admission_reports_deny_guidance() {
        let finding = classify_swarm_admission(
            test_swarm_capacity_plan(),
            healthy_resource_sample(),
            SwarmLiveLoad::empty().with_active_tool_calls(8),
            &[],
        );

        assert_eq!(finding.severity, Severity::Fail);
        let data = finding_data(&finding);
        assert_eq!(data["action"], "deny");
        assert_eq!(data["pressure_dimension"], "active_tool_calls");
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("Do not launch new swarm work")
        );
    }

    #[test]
    fn swarm_admission_marks_stale_input_degraded() {
        let warnings = vec!["host load average unavailable".to_string()];
        let finding = classify_swarm_admission(
            test_swarm_capacity_plan(),
            healthy_resource_sample(),
            SwarmLiveLoad::empty().with_active_agents(1),
            &warnings,
        );

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(data["action"], "admit");
        assert_eq!(
            data["stale_data_warnings"][0],
            "host load average unavailable"
        );
        assert!(
            finding
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("stale_data_warnings")
        );
    }

    #[test]
    fn swarm_admission_blocks_corrupted_coordination() {
        let warnings = vec!["Beads ledger has malformed JSONL rows".to_string()];
        let finding = swarm_admission_blocked_finding(
            Severity::Fail,
            "Live swarm admission decision denies new work",
            "Beads ledger has 1 malformed JSONL row; coordination state is corrupted".to_string(),
            &warnings,
        );

        assert_eq!(finding.severity, Severity::Fail);
        let data = finding_data(&finding);
        assert_eq!(data["action"], "deny");
        assert!(data["admission_decision"].is_null());
        assert_eq!(
            data["stale_data_warnings"][0],
            "Beads ledger has malformed JSONL rows"
        );
    }

    #[test]
    fn swarm_git_porcelain_summary_counts_dirty_kinds() {
        let summary =
            summarize_git_porcelain(" M src/doctor.rs\nA  README.md\n?? notes.md\n D stale.rs\n");

        assert_eq!(summary.total, 4);
        assert_eq!(summary.staged, 1);
        assert_eq!(summary.unstaged, 2);
        assert_eq!(summary.untracked, 1);
        assert_eq!(summary.deleted, 1);
    }

    #[test]
    fn swarm_agent_mail_status_warns_on_ack_required() {
        let value = serde_json::json!({
            "inbox": {
                "unread": 2,
                "urgent": 0,
                "ack_required": 1
            }
        });

        let finding = classify_agent_mail_status(&value);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.unwrap().contains("ack_required=1"));
    }

    #[test]
    fn swarm_br_status_warns_on_sync_drift() {
        let value = serde_json::json!({
            "dirty_count": 2,
            "jsonl_newer": false,
            "db_newer": true
        });

        let finding = classify_br_sync_status(&value);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.unwrap().contains("dirty_count=2"));
    }

    #[test]
    fn swarm_br_status_passes_when_clean() {
        let value = serde_json::json!({
            "dirty_count": 0,
            "jsonl_newer": false,
            "db_newer": false
        });

        let finding = classify_br_sync_status(&value);

        assert_eq!(finding.severity, Severity::Pass);
    }

    #[test]
    fn swarm_agent_mail_reservations_detect_conflicts() {
        let value = serde_json::json!({
            "reservations": [
                {
                    "path": "src/doctor.rs",
                    "agent": "CalmBridge",
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:00:00Z"
                }
            ],
            "conflicts": [
                {"path": "src/doctor.rs", "holder": "OtherAgent"}
            ]
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("conflicts"));
        let data = finding.data.unwrap();
        assert_eq!(data["schema"], SWARM_DOCTOR_RESERVATION_HEATMAP_SCHEMA);
        assert_eq!(data["totals"]["active_count"], 1);
    }

    #[test]
    fn swarm_agent_mail_reservations_pass_when_clear() {
        let value = serde_json::json!({
            "reservations": [],
            "expiring": 0,
            "conflicts": []
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Pass);
    }

    #[test]
    fn swarm_agent_mail_reservation_heatmap_detects_overlapping_globs() {
        let value = serde_json::json!({
            "reservations": [
                {
                    "path_pattern": "src/**",
                    "agent": "CalmBridge",
                    "reason": "bd-overlap parent lane",
                    "exclusive": true,
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:00:00Z"
                },
                {
                    "path_pattern": "src/doctor.rs",
                    "agent": "DarkGoose",
                    "reason": "bd-overlap.1 concrete lane",
                    "exclusive": true,
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:30:00Z"
                }
            ]
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding.data.unwrap();
        assert_eq!(data["totals"]["conflict_group_count"], 1);
        assert_eq!(
            data["heatmap"]["conflicts"][0]["reason"],
            "overlapping_active_reservations"
        );
        assert_eq!(data["heatmap"]["by_path_pattern"][0]["conflict_count"], 1);
    }

    #[test]
    fn swarm_agent_mail_reservation_heatmap_ignores_expired_conflicts_but_counts_recent() {
        let value = serde_json::json!({
            "reservations": [
                {
                    "path_pattern": "src/**",
                    "agent": "CalmBridge",
                    "exclusive": true,
                    "expires_ts": "2026-05-09T07:45:00Z",
                    "created_at": "2026-05-09T06:00:00Z"
                },
                {
                    "path_pattern": "src/doctor.rs",
                    "agent": "DarkGoose",
                    "exclusive": true,
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:30:00Z"
                }
            ]
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding.data.unwrap();
        assert_eq!(data["totals"]["expired_count"], 1);
        assert_eq!(data["totals"]["recent_inactive_count"], 1);
        assert_eq!(data["totals"]["conflict_group_count"], 0);
    }

    #[test]
    fn swarm_agent_mail_reservation_heatmap_allows_shared_overlaps() {
        let value = serde_json::json!({
            "reservations": [
                {
                    "path_pattern": "src/**",
                    "agent": "CalmBridge",
                    "reason": "bd-shared",
                    "exclusive": false,
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:00:00Z"
                },
                {
                    "path_pattern": "src/doctor.rs",
                    "agent": "DarkGoose",
                    "reason": "bd-shared",
                    "exclusive": false,
                    "expires_ts": "2026-05-09T09:00:00Z",
                    "created_at": "2026-05-09T07:30:00Z"
                }
            ]
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding.data.unwrap();
        assert_eq!(data["totals"]["shared_active_count"], 2);
        assert_eq!(data["totals"]["exclusive_active_count"], 0);
        assert_eq!(data["totals"]["conflict_group_count"], 0);
    }

    #[test]
    fn swarm_agent_mail_reservation_heatmap_recommends_stale_holders() {
        let value = serde_json::json!({
            "reservations": [
                {
                    "path_pattern": "src/doctor.rs",
                    "agent": "CalmBridge",
                    "reason": "bd-stale stale holder",
                    "exclusive": true,
                    "expires_ts": "2026-05-10T08:00:00Z",
                    "created_at": "2026-05-08T07:00:00Z"
                }
            ]
        });

        let finding = classify_agent_mail_reservations_at(&value, heatmap_test_now());

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("stale holder"));
        let data = finding.data.unwrap();
        assert_eq!(data["totals"]["stale_holder_recommendation_count"], 1);
        assert_eq!(
            data["stale_holder_recommendations"][0]["reason"],
            "active_exclusive_reservation_older_than_threshold"
        );
    }

    #[test]
    fn swarm_agent_mail_contacts_warns_on_pending_requests() {
        let value = serde_json::json!({
            "data": {
                "count": 2,
                "contacts": [
                    {
                        "from": "SunnyBeacon",
                        "to": "MagentaOak",
                        "status": "pending",
                        "policy": "auto",
                        "reason": "coordination",
                        "updated": "1h"
                    },
                    {
                        "from": "MagentaOak",
                        "to": "RusticGorge",
                        "status": "approved",
                        "policy": "auto",
                        "reason": "coordination",
                        "updated": "2h"
                    }
                ]
            }
        });

        let finding = classify_agent_mail_contacts(&value);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("pending"));
        let data = finding_data(&finding);
        assert_eq!(data["pending_count"], serde_json::json!(1));
        assert_eq!(data["approved_count"], serde_json::json!(1));
    }

    #[test]
    fn swarm_agent_mail_contacts_warns_on_degraded_rows() {
        let value = serde_json::json!({
            "contacts": [
                {
                    "from": "[unknown-agent-1218]",
                    "to": "MagentaOak",
                    "status": "approved",
                    "policy": "unknown",
                    "reason": "coordination",
                    "updated": "4m"
                },
                {
                    "from": "MagentaOak",
                    "to": "SunnyBeacon",
                    "status": "mystery",
                    "policy": "auto",
                    "reason": "coordination",
                    "updated": "5m"
                }
            ]
        });

        let finding = classify_agent_mail_contacts(&value);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("degraded"));
        let data = finding_data(&finding);
        assert_eq!(data["degraded_count"], serde_json::json!(2));
        assert_eq!(data["unknown_status_count"], serde_json::json!(1));
    }

    #[test]
    fn swarm_agent_mail_contacts_passes_when_links_are_settled() {
        let value = serde_json::json!({
            "contacts": [
                {
                    "from": "MagentaOak",
                    "to": "SunnyBeacon",
                    "status": "approved",
                    "policy": "auto",
                    "reason": "coordination",
                    "updated": "3m"
                },
                {
                    "from": "CopperOx",
                    "to": "MagentaOak",
                    "status": "blocked",
                    "policy": "contacts_only",
                    "reason": "not needed",
                    "updated": "10m"
                }
            ]
        });

        let finding = classify_agent_mail_contacts(&value);

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["contact_count"], serde_json::json!(2));
        assert_eq!(data["blocked_count"], serde_json::json!(1));
    }

    #[test]
    fn swarm_agent_mail_build_slots_pass_when_none_active() {
        let finding = classify_agent_mail_build_slots(&[], 0, build_slot_test_now());

        assert_eq!(finding.severity, Severity::Pass);
        let data = finding_data(&finding);
        assert_eq!(data["schema"], SWARM_DOCTOR_BUILD_SLOT_SCHEMA);
        assert_eq!(data["source_supported"], serde_json::json!(true));
        assert_eq!(data["active_count"], serde_json::json!(0));
        assert_eq!(data["slots"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn swarm_agent_mail_build_slots_reports_active_shared_slot() {
        let values = vec![serde_json::json!({
            "slot": "cargo-check",
            "agent": "BlueLake",
            "branch": "main",
            "exclusive": false,
            "acquired_ts": "2026-05-09T07:45:00Z",
            "expires_ts": "2026-05-09T10:00:00Z"
        })];

        let finding = classify_agent_mail_build_slots(&values, 0, build_slot_test_now());

        assert_eq!(finding.severity, Severity::Info);
        let data = finding_data(&finding);
        assert_eq!(data["active_count"], serde_json::json!(1));
        assert_eq!(data["active_shared_count"], serde_json::json!(1));
        assert_eq!(data["slots"][0]["slot"], "cargo-check");
        assert_eq!(data["slots"][0]["agent"], "BlueLake");
        assert_eq!(data["slots"][0]["exclusive"], serde_json::json!(false));
        assert_eq!(data["slots"][0]["expires_ts"], "2026-05-09T10:00:00Z");
        assert_eq!(data["slots"][0]["classification"], "active");
    }

    #[test]
    fn swarm_agent_mail_build_slots_warn_on_active_exclusive_slot() {
        let values = vec![serde_json::json!({
            "slot": "cargo-clippy",
            "agent": "GreenBridge",
            "branch": "main",
            "exclusive": true,
            "expires_ts": "2026-05-09T10:00:00Z"
        })];

        let finding = classify_agent_mail_build_slots(&values, 0, build_slot_test_now());

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("exclusive"));
        let data = finding_data(&finding);
        assert_eq!(data["active_count"], serde_json::json!(1));
        assert_eq!(data["active_exclusive_count"], serde_json::json!(1));
        assert_eq!(data["slots"][0]["agent"], "GreenBridge");
        assert_eq!(data["slots"][0]["classification"], "active");
    }

    #[test]
    fn swarm_agent_mail_build_slots_classify_expired_and_soon_expiring_slots() {
        let values = vec![
            serde_json::json!({
                "slot": "cargo-test",
                "agent": "AmberField",
                "branch": "main",
                "exclusive": false,
                "expires_ts": "2026-05-09T07:59:00Z"
            }),
            serde_json::json!({
                "slot": "cargo-check",
                "agent": "CyanHill",
                "branch": "main",
                "exclusive": false,
                "expires_ts": "2026-05-09T08:20:00Z"
            }),
        ];

        let finding = classify_agent_mail_build_slots(&values, 0, build_slot_test_now());

        assert_eq!(finding.severity, Severity::Warn);
        let data = finding_data(&finding);
        assert_eq!(data["active_count"], serde_json::json!(1));
        assert_eq!(data["soon_expiring_count"], serde_json::json!(1));
        assert_eq!(data["stale_count"], serde_json::json!(1));
        let classifications = data["slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| slot["classification"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(classifications.contains(&"soon_expiring"));
        assert!(classifications.contains(&"stale_expired"));
    }

    #[test]
    fn swarm_agent_mail_build_slots_report_missing_support() {
        let finding =
            agent_mail_build_slots_unavailable_finding("build-slot source is unavailable");

        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.title, "Agent Mail build slots unavailable");
        let data = finding_data(&finding);
        assert_eq!(data["source_supported"], serde_json::json!(false));
        assert_eq!(data["reason"], "build-slot source is unavailable");
    }

    #[test]
    fn swarm_redacts_sensitive_probe_output() {
        let outcome = CommandOutcome {
            timed_out: false,
            success: false,
            status_code: Some(1),
            stdout: "status ok\nOPENAI_API_KEY=secret-value\n".to_string(),
            stderr: String::new(),
        };

        let snippet = redacted_output_snippet(&outcome);

        assert!(snippet.contains("status ok"));
        assert!(snippet.contains("[redacted sensitive output line]"));
        assert!(!snippet.contains("secret-value"));
    }

    #[test]
    fn swarm_rch_classifier_reports_retrieval_disk_pressure_without_code_regression() {
        let outcome = CommandOutcome {
            timed_out: false,
            success: false,
            status_code: Some(1),
            stdout: "remote command succeeded; exit status 0\n".to_string(),
            stderr: "failed to retrieve artifact bundle: No space left on device while copying to CARGO_TARGET_DIR\n".to_string(),
        };

        assert_eq!(
            classify_rch_failure(&outcome),
            RchFailureKind::ArtifactRetrievalDiskPressure
        );
        let finding = rch_failure_finding(&outcome);
        let data = finding_data(&finding);

        assert_eq!(data["classification"], "artifact_retrieval_disk_pressure");
        assert_eq!(data["code_regression"], serde_json::json!(false));
        assert_eq!(data["fail_closed"], serde_json::json!(false));
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("/data/tmp/pi_agent_rust_cargo/<agent>/")
        );
    }

    #[test]
    fn swarm_rch_classifier_reports_local_target_tmpdir_disk_pressure() {
        let outcome = CommandOutcome {
            timed_out: false,
            success: false,
            status_code: Some(1),
            stdout: String::new(),
            stderr: "failed to create target/debug/.fingerprint/pi: ENOSPC (No space left on device); TMPDIR=/tmp\n".to_string(),
        };

        assert_eq!(
            classify_rch_failure(&outcome),
            RchFailureKind::LocalTargetDiskPressure
        );
        let finding = rch_failure_finding(&outcome);
        let data = finding_data(&finding);

        assert_eq!(data["classification"], "local_target_tmpdir_disk_pressure");
        assert_eq!(data["code_regression"], serde_json::json!(false));
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/<agent>/target")
        );
    }

    #[test]
    fn swarm_rch_classifier_reports_true_remote_compile_failure() {
        let outcome = CommandOutcome {
            timed_out: false,
            success: false,
            status_code: Some(101),
            stdout: String::new(),
            stderr: "error[E0308]: mismatched types\nerror: could not compile `pi` due to previous error\n".to_string(),
        };

        assert_eq!(
            classify_rch_failure(&outcome),
            RchFailureKind::RemoteBuildOrTestFailure
        );
        let finding = rch_failure_finding(&outcome);
        let data = finding_data(&finding);

        assert_eq!(data["classification"], "remote_build_or_test_failure");
        assert_eq!(data["code_regression"], serde_json::json!(true));
        assert_eq!(data["raw_status"]["exit_code"], serde_json::json!(101));
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("real compile/test failure")
        );
    }

    #[test]
    fn swarm_rch_classifier_keeps_unknown_fail_closed_with_raw_status() {
        let outcome = CommandOutcome {
            timed_out: false,
            success: false,
            status_code: Some(7),
            stdout: String::new(),
            stderr: "worker transport returned opaque failure code".to_string(),
        };

        assert_eq!(classify_rch_failure(&outcome), RchFailureKind::Unknown);
        let finding = rch_failure_finding(&outcome);
        let data = finding_data(&finding);

        assert_eq!(data["classification"], "unknown_rch_failure");
        assert!(data["code_regression"].is_null());
        assert_eq!(data["fail_closed"], serde_json::json!(true));
        assert_eq!(data["raw_status"]["exit_code"], serde_json::json!(7));
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("do not classify this as disk pressure or a code regression")
        );
    }

    #[test]
    fn swarm_df_parser_and_formatting_are_stable() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 12000 88000 13% /data\n";

        assert_eq!(parse_df_available_kb(output), Some(88_000));
        assert_eq!(format_available_kb(88_000), "85.9 MiB");
        assert_eq!(format_available_kb(11 * 1024 * 1024), "11.0 GiB");
    }

    #[test]
    fn swarm_temp_dir_posture_passes_for_expected_scratch_root() {
        let finding = swarm_temp_dir_finding(
            "CARGO_TARGET_DIR",
            Path::new("/data/tmp/pi_agent_rust_cargo/sunnybeacon/target"),
            Some(12 * 1024 * 1024),
            None,
        );
        let data = finding_data(&finding);

        assert_eq!(finding.severity, Severity::Pass);
        assert_eq!(data["schema"], SWARM_DOCTOR_TEMP_DIR_SCHEMA);
        assert_eq!(data["env_name"], "CARGO_TARGET_DIR");
        assert_eq!(data["under_expected_root"], serde_json::json!(true));
        assert_eq!(data["available_kb"], serde_json::json!(12 * 1024 * 1024));
    }

    #[test]
    fn swarm_temp_dir_posture_warns_outside_scratch_root_even_with_headroom() {
        let finding = swarm_temp_dir_finding(
            "TMPDIR",
            Path::new("/tmp/pi_agent_rust_cargo/sunnybeacon/tmp"),
            Some(64 * 1024 * 1024),
            None,
        );
        let data = finding_data(&finding);

        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.title.contains("outside swarm scratch root"));
        assert_eq!(data["schema"], SWARM_DOCTOR_TEMP_DIR_SCHEMA);
        assert_eq!(data["under_expected_root"], serde_json::json!(false));
        assert_eq!(data["expected_root"], SWARM_CARGO_SCRATCH_ROOT);
        assert!(
            finding
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains(SWARM_CARGO_SCRATCH_ROOT)
        );
    }

    #[test]
    fn session_healthy_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        std::fs::write(&path, "").unwrap();
        assert!(!is_session_healthy(&path));
    }

    #[test]
    fn session_healthy_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.jsonl");
        std::fs::write(
            &path,
            r#"{"type":"session","version":3,"id":"doctor-jsonl","timestamp":"2026-01-01T00:00:00.000Z","cwd":"/tmp"}"#,
        )
        .unwrap();
        assert!(is_session_healthy(&path));
    }

    #[test]
    fn session_healthy_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.jsonl");
        std::fs::write(&path, "not json at all\n").unwrap();
        assert!(!is_session_healthy(&path));
    }

    #[test]
    fn session_healthy_rejects_non_header_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("array.jsonl");
        std::fs::write(&path, "[1,2,3]\n").unwrap();
        assert!(!is_session_healthy(&path));
    }

    #[cfg(feature = "sqlite-sessions")]
    #[test]
    fn session_healthy_valid_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.sqlite");
        let header = SessionHeader {
            id: "doctor-sqlite".to_string(),
            ..SessionHeader::default()
        };
        futures::executor::block_on(async {
            crate::session_sqlite::save_session(&path, &header, &[])
                .await
                .expect("save sqlite session");
        });
        assert!(is_session_healthy(&path));
    }

    #[cfg(feature = "sqlite-sessions")]
    #[test]
    fn session_healthy_rejects_invalid_sqlite_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.sqlite");
        let header = SessionHeader {
            id: "doctor-sqlite".to_string(),
            ..SessionHeader::default()
        };
        futures::executor::block_on(async {
            crate::session_sqlite::save_session(&path, &header, &[])
                .await
                .expect("save sqlite session");
        });
        let invalid_header = SessionHeader {
            r#type: "not-session".to_string(),
            ..header
        };
        let invalid_json =
            serde_json::to_string(&invalid_header).expect("serialize invalid session header");
        let config = sqlmodel_sqlite::SqliteConfig::file(path.to_string_lossy())
            .flags(sqlmodel_sqlite::OpenFlags::create_read_write());
        let conn = sqlmodel_sqlite::SqliteConnection::open(&config).expect("open sqlite db");
        conn.execute_sync(
            "UPDATE pi_session_header SET json = ?1",
            &[sqlmodel_core::Value::Text(invalid_json)],
        )
        .expect("corrupt sqlite header row");
        assert!(!is_session_healthy(&path));
    }

    #[test]
    fn check_dir_creates_missing_with_fix() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("sub/nested");
        let mut findings = Vec::new();
        check_dir(CheckCategory::Dirs, "test", &missing, true, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
        assert_eq!(findings[0].fixability, Fixability::Fixed);
        assert!(missing.is_dir());
    }

    #[test]
    fn check_dir_warns_missing_without_fix() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("sub/nested");
        let mut findings = Vec::new();
        check_dir(CheckCategory::Dirs, "test", &missing, false, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].fixability, Fixability::AutoFixable);
        assert!(!missing.exists());
    }

    #[test]
    fn check_shell_finds_bash() {
        let mut findings = Vec::new();
        check_tool(
            CheckCategory::Shell,
            "bash",
            &["--version"],
            Severity::Fail,
            ToolCheckMode::ProbeExecution,
            &mut findings,
        );
        // bash should be available in CI/dev environments
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }

    #[cfg(unix)]
    #[test]
    fn check_tool_falls_back_when_probe_args_are_unsupported() {
        let mut findings = Vec::new();
        check_tool(
            CheckCategory::Shell,
            "sh",
            &["--version"],
            Severity::Fail,
            ToolCheckMode::ProbeExecution,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Pass);
    }

    #[cfg(unix)]
    #[test]
    fn check_tool_reports_invocation_failure_for_broken_executable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("broken_tool.sh");
        // Mark a non-binary, non-script blob as executable so spawn fails with
        // "exec format error" rather than "not found".
        std::fs::write(&script, "not an executable format").unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let mut findings = Vec::new();
        check_tool(
            CheckCategory::Shell,
            script.to_str().unwrap(),
            &["--version"],
            Severity::Fail,
            ToolCheckMode::ProbeExecution,
            &mut findings,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(findings[0].title.contains("invocation failed"));
    }

    #[test]
    fn check_settings_file_rejects_non_object_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "[1,2,3]").unwrap();
        let mut findings = Vec::new();
        check_settings_file(CheckCategory::Config, &path, "Settings", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert!(
            findings[0]
                .title
                .contains("top-level value must be a JSON object")
        );
    }

    #[test]
    fn fixability_display() {
        // Ensure serialization works
        let json = serde_json::to_string(&Fixability::AutoFixable).unwrap();
        assert!(json.contains("autoFixable") || json.contains("auto"));
    }

    #[test]
    fn run_doctor_path_mode_defaults_to_extension_checks_only() {
        let dir = tempfile::tempdir().unwrap();
        let opts = DoctorOptions {
            cwd: dir.path(),
            extension_path: Some("missing-ext"),
            policy_override: None,
            fix: false,
            only: None,
        };
        let report = run_doctor(&opts).unwrap();
        assert!(
            !report.findings.is_empty(),
            "missing extension path should produce at least one finding"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|f| matches!(f.category, CheckCategory::Extensions)),
            "path mode should not run unrelated environment categories by default"
        );
    }

    #[test]
    fn run_doctor_only_extensions_without_path_reports_error_finding() {
        let mut only = HashSet::new();
        only.insert(CheckCategory::Extensions);
        let dir = tempfile::tempdir().unwrap();
        let opts = DoctorOptions {
            cwd: dir.path(),
            extension_path: None,
            policy_override: None,
            fix: false,
            only: Some(only),
        };
        let report = run_doctor(&opts).unwrap();
        assert!(
            report.findings.iter().any(|f| {
                matches!(f.category, CheckCategory::Extensions)
                    && matches!(f.severity, Severity::Fail)
            }),
            "extensions-only mode without a path should emit a clear failure finding"
        );
    }

    #[test]
    fn run_doctor_extension_path_uses_supplied_cwd_for_policy_resolution() {
        let project = tempfile::tempdir().expect("project dir");
        let config_dir = project.path().join(".pi");
        std::fs::create_dir_all(&config_dir).expect("create project config dir");
        std::fs::write(
            config_dir.join("settings.json"),
            r#"{ "extensionPolicy": { "profile": "safe" } }"#,
        )
        .expect("write project settings");
        write_extension_fixture(
            project.path(),
            r#"
const { exec } = require("child_process");
export default function(pi) {
    pi.exec("ls");
}
"#,
        );

        let opts = DoctorOptions {
            cwd: project.path(),
            extension_path: Some("ext"),
            policy_override: None,
            fix: false,
            only: None,
        };
        let report = run_doctor(&opts).expect("doctor report");

        assert!(
            report.findings.iter().any(|f| f.title.contains("exec")),
            "doctor should honor the supplied cwd's safe policy and flag exec use"
        );
    }

    #[test]
    fn run_doctor_extension_path_reports_config_load_failure_without_aborting() {
        let project = tempfile::tempdir().expect("project dir");
        let config_dir = project.path().join(".pi");
        std::fs::create_dir_all(&config_dir).expect("create project config dir");
        std::fs::write(config_dir.join("settings.json"), r#"{ "extensionPolicy": "#)
            .expect("write malformed project settings");
        write_extension_fixture(
            project.path(),
            r#"
import net from "node:net";
"#,
        );

        let opts = DoctorOptions {
            cwd: project.path(),
            extension_path: Some("ext"),
            policy_override: None,
            fix: false,
            only: None,
        };
        let report = run_doctor(&opts).expect("doctor report");

        assert!(
            report
                .findings
                .iter()
                .all(|f| matches!(f.category, CheckCategory::Extensions)),
            "extension path mode should keep findings scoped to extensions"
        );
        assert!(
            report.findings.iter().any(|f| {
                f.title
                    .as_str()
                    .eq("Failed to load configuration for extension policy resolution")
            }),
            "doctor should surface config load failures as findings instead of returning Err"
        );
        assert!(
            report.findings.iter().any(|f| f.title.contains("node:net")),
            "doctor should continue extension analysis after a config load failure"
        );
    }

    #[test]
    fn run_doctor_extension_path_config_load_failure_falls_back_to_safe_policy() {
        let project = tempfile::tempdir().expect("project dir");
        let config_dir = project.path().join(".pi");
        std::fs::create_dir_all(&config_dir).expect("create project config dir");
        std::fs::write(config_dir.join("settings.json"), r#"{ "extensionPolicy": "#)
            .expect("write malformed project settings");
        write_extension_fixture(
            project.path(),
            r#"
export default function(pi) {
    pi.exec("ls");
}
"#,
        );

        let opts = DoctorOptions {
            cwd: project.path(),
            extension_path: Some("ext"),
            policy_override: None,
            fix: false,
            only: None,
        };
        let report = run_doctor(&opts).expect("doctor report");

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.title.as_str().eq("Extension ext: incompatible")),
            "doctor should fail closed under a safe fallback when config loading fails"
        );
        assert!(
            report.findings.iter().any(|f| f.title.contains("exec")),
            "safe fallback should still flag denied exec usage"
        );
    }

    #[test]
    fn run_doctor_extension_path_config_load_failure_honors_cli_policy_override() {
        let project = tempfile::tempdir().expect("project dir");
        let config_dir = project.path().join(".pi");
        std::fs::create_dir_all(&config_dir).expect("create project config dir");
        std::fs::write(config_dir.join("settings.json"), r#"{ "extensionPolicy": "#)
            .expect("write malformed project settings");
        write_extension_fixture(
            project.path(),
            r#"
export default function(pi) {
    pi.exec("ls");
}
"#,
        );

        let opts = DoctorOptions {
            cwd: project.path(),
            extension_path: Some("ext"),
            policy_override: Some("permissive"),
            fix: false,
            only: None,
        };
        let report = run_doctor(&opts).expect("doctor report");

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.title.as_str().eq("Extension ext: compatible")),
            "explicit CLI overrides should still control fallback analysis"
        );
        assert!(
            !report.findings.iter().any(|f| f.title.contains("exec")),
            "permissive override should suppress safe-only exec denial findings"
        );
    }

    mod proptest_doctor {
        use super::*;
        use proptest::prelude::*;

        const ALL_SEVERITIES: &[Severity] = &[
            Severity::Pass,
            Severity::Info,
            Severity::Warn,
            Severity::Fail,
        ];

        const CATEGORY_ALIASES: &[&str] = &[
            "config",
            "dirs",
            "directories",
            "auth",
            "authentication",
            "shell",
            "sessions",
            "extensions",
            "ext",
        ];

        proptest! {
            /// Severity ordering is total: Pass < Info < Warn < Fail.
            #[test]
            fn severity_ordering_total(a in 0..4usize, b in 0..4usize) {
                let sa = ALL_SEVERITIES[a];
                let sb = ALL_SEVERITIES[b];
                match a.cmp(&b) {
                    std::cmp::Ordering::Less => assert!(sa < sb),
                    std::cmp::Ordering::Equal => assert!(sa.eq(&sb)),
                    std::cmp::Ordering::Greater => assert!(sa > sb),
                }
            }

            /// Severity display produces uppercase 4-char labels.
            #[test]
            fn severity_display_uppercase(idx in 0..4usize) {
                let s = ALL_SEVERITIES[idx];
                let display = s.to_string();
                assert_eq!(display.len(), 4);
                assert!(display.chars().all(|c| c.is_ascii_uppercase()));
            }

            /// `CheckCategory::from_str` accepts all known aliases.
            #[test]
            fn check_category_known_aliases(idx in 0..CATEGORY_ALIASES.len()) {
                let alias = CATEGORY_ALIASES[idx];
                assert!(alias.parse::<CheckCategory>().is_ok());
            }

            /// `CheckCategory::from_str` is case-insensitive.
            #[test]
            fn check_category_case_insensitive(idx in 0..CATEGORY_ALIASES.len()) {
                let alias = CATEGORY_ALIASES[idx];
                let upper = alias.to_uppercase();
                let lower_result = alias.parse::<CheckCategory>();
                let upper_result = upper.parse::<CheckCategory>();
                assert_eq!(lower_result, upper_result);
            }

            /// Unknown category names are rejected.
            #[test]
            fn check_category_unknown_rejected(s in "[a-z]{10,20}") {
                assert!(s.parse::<CheckCategory>().is_err());
            }

            /// `CheckCategory::label` returns non-empty strings.
            #[test]
            fn check_category_label_non_empty(idx in 0..6usize) {
                let cats = [
                    CheckCategory::Config,
                    CheckCategory::Dirs,
                    CheckCategory::Auth,
                    CheckCategory::Shell,
                    CheckCategory::Sessions,
                    CheckCategory::Extensions,
                ];
                let label = cats[idx].label();
                assert!(!label.is_empty());
                // Label starts with uppercase
                assert!(label.starts_with(|c: char| c.is_uppercase()));
            }

            /// `DoctorReport::from_findings` summary counts match input.
            #[test]
            fn from_findings_counts_match(
                pass in 0..5usize,
                info in 0..5usize,
                warn in 0..5usize,
                fail in 0..5usize
            ) {
                let mut findings = Vec::new();
                for _ in 0..pass {
                    findings.push(Finding::pass(CheckCategory::Config, "test"));
                }
                for _ in 0..info {
                    findings.push(Finding::info(CheckCategory::Config, "test"));
                }
                for _ in 0..warn {
                    findings.push(Finding::warn(CheckCategory::Config, "test"));
                }
                for _ in 0..fail {
                    findings.push(Finding::fail(CheckCategory::Config, "test"));
                }

                let report = DoctorReport::from_findings(findings);
                assert_eq!(report.summary.pass, pass);
                assert_eq!(report.summary.info, info);
                assert_eq!(report.summary.warn, warn);
                assert_eq!(report.summary.fail, fail);
            }

            /// `DoctorReport::from_findings` overall severity is max of inputs.
            #[test]
            fn from_findings_overall_severity(
                pass in 0..3usize,
                info in 0..3usize,
                warn in 0..3usize,
                fail in 0..3usize
            ) {
                let mut findings = Vec::new();
                for _ in 0..pass {
                    findings.push(Finding::pass(CheckCategory::Config, "test"));
                }
                for _ in 0..info {
                    findings.push(Finding::info(CheckCategory::Config, "test"));
                }
                for _ in 0..warn {
                    findings.push(Finding::warn(CheckCategory::Config, "test"));
                }
                for _ in 0..fail {
                    findings.push(Finding::fail(CheckCategory::Config, "test"));
                }

                let report = DoctorReport::from_findings(findings);

                if fail > 0 {
                    assert_eq!(report.overall, Severity::Fail);
                } else if warn > 0 {
                    assert_eq!(report.overall, Severity::Warn);
                } else {
                    assert_eq!(report.overall, Severity::Pass);
                }
            }

            /// `is_known_config_key` accepts both camelCase and snake_case forms.
            #[test]
            fn config_key_pairs(idx in 0..10usize) {
                let pairs = [
                    ("hideThinkingBlock", "hide_thinking_block"),
                    ("showHardwareCursor", "show_hardware_cursor"),
                    ("defaultProvider", "default_provider"),
                    ("defaultModel", "default_model"),
                    ("defaultThinkingLevel", "default_thinking_level"),
                    ("enabledModels", "enabled_models"),
                    ("steeringMode", "steering_mode"),
                    ("followUpMode", "follow_up_mode"),
                    ("quietStartup", "quiet_startup"),
                    ("collapseChangelog", "collapse_changelog"),
                ];
                let (camel, snake) = pairs[idx];
                assert!(is_known_config_key(camel), "camelCase key {camel} should be known");
                assert!(is_known_config_key(snake), "snake_case key {snake} should be known");
            }

            /// `is_known_config_key` rejects garbage keys.
            #[test]
            fn config_key_rejects_garbage(s in "[A-Z]{20,30}") {
                assert!(!is_known_config_key(&s));
            }

            /// Severity serde roundtrip is lowercase.
            #[test]
            fn severity_serde_lowercase(idx in 0..4usize) {
                let s = ALL_SEVERITIES[idx];
                let json = serde_json::to_string(&s).unwrap();
                let expected = format!("\"{}\"", s.to_string().to_lowercase());
                assert_eq!(json, expected);
            }

            /// Finding builder chain preserves fields.
            #[test]
            fn finding_builder_chain(title in "[a-z ]{1,20}", detail in "[a-z ]{1,20}") {
                let f = Finding::warn(CheckCategory::Shell, title.clone())
                    .with_detail(detail.clone())
                    .with_remediation("fix it")
                    .auto_fixable();
                assert_eq!(f.title, title);
                assert_eq!(f.detail.as_deref(), Some(detail.as_str()));
                assert_eq!(f.remediation.as_deref(), Some("fix it"));
                assert_eq!(f.fixability, Fixability::AutoFixable);
                assert_eq!(f.severity, Severity::Warn);
            }

            /// `fixed()` resets severity to Pass.
            #[test]
            fn finding_fixed_resets_severity(idx in 0..4usize) {
                let builders = [
                    Finding::pass(CheckCategory::Config, "t"),
                    Finding::info(CheckCategory::Config, "t"),
                    Finding::warn(CheckCategory::Config, "t"),
                    Finding::fail(CheckCategory::Config, "t"),
                ];
                let fixed = builders[idx].clone().fixed();
                assert_eq!(fixed.severity, Severity::Pass);
                assert_eq!(fixed.fixability, Fixability::Fixed);
            }
        }
    }
}
