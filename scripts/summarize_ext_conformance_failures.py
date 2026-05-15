#!/usr/bin/env python3
"""Summarize extension conformance failures into actionable triage.

This is a read-only operator report. It consumes existing extension
conformance JSON/JSONL reports plus fixture/manifest metadata, collapses
duplicate failure signatures, compares current failures with the committed
baseline, and emits JSON plus concise Markdown. It never mutates conformance
artifacts, Beads, git, RCH, Agent Mail, or source files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_SCHEMA = "pi.ext.conformance_failure_triage.v1"
POLICY = "read_only_no_mutation"
DEFAULT_STALE_DAYS = 45
DEFAULT_BASELINE = (
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "conformance_baseline.json"
)
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "ext_conformance" / "VALIDATED_MANIFEST.json"
DEFAULT_INVENTORY = REPO_ROOT / "tests" / "ext_conformance" / "reports" / "inventory.json"
DEFAULT_REPORTS = [
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "gate" / "must_pass_events.jsonl",
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "conformance_events.jsonl",
    REPO_ROOT
    / "tests"
    / "ext_conformance"
    / "reports"
    / "conformance"
    / "conformance_events.jsonl",
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "smoke_triage.json",
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "smoke" / "triage.json",
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "negative" / "triage.json",
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "guard" / "triage.json",
]
FAIL_STATUSES = {"fail", "failed", "error"}
PASS_STATUSES = {"pass", "passed", "ok", "success"}
BASELINE_STALE_WARNING = "baseline_stale"


@dataclass(frozen=True)
class LoadedJson:
    path: str | None
    payload: Any | None
    error: str | None


@dataclass(frozen=True)
class ReportRecord:
    record: dict[str, Any]
    source: Path
    line: int | None = None
    json_path: str | None = None

    @property
    def location(self) -> str:
        rel = repo_relative(self.source)
        if self.line is not None:
            return f"{rel}:{self.line}"
        if self.json_path:
            return f"{rel}:{self.json_path}"
        return rel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now(now: datetime) -> str:
    return now.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def repo_relative(path: Path | str | None, repo_root: Path = REPO_ROOT) -> str:
    if path is None:
        return ""
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(repo_root.resolve()).as_posix()
    except (OSError, ValueError):
        return candidate.as_posix()


def resolve_path(path: Path | None, repo_root: Path) -> Path | None:
    if path is None:
        return None
    return path if path.is_absolute() else repo_root / path


def json_dumps(payload: Any, *, pretty: bool) -> str:
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def read_json(path: Path | None) -> LoadedJson:
    if path is None:
        return LoadedJson(path=None, payload=None, error=None)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return LoadedJson(path=str(path), payload=None, error=str(exc))
    try:
        return LoadedJson(path=str(path), payload=json.loads(text), error=None)
    except json.JSONDecodeError as exc:
        return LoadedJson(path=str(path), payload=None, error=f"invalid JSON: {exc}")


def extension_id_from_record(record: dict[str, Any]) -> str | None:
    value = record.get("extension_id")
    if isinstance(value, str) and value:
        return value

    extension = record.get("extension")
    scenario_id = record.get("id")
    schema = record.get("schema")
    if (
        isinstance(extension, str)
        and extension
        and (
            (isinstance(scenario_id, str) and scenario_id.startswith("scn-"))
            or (isinstance(schema, str) and "scenario" in schema)
        )
    ):
        return extension

    value = record.get("id")
    if isinstance(value, str) and value:
        return value
    return None


def case_id_from_record(record: dict[str, Any], extension_id: str | None) -> str | None:
    value = record.get("id")
    if isinstance(value, str) and value and value != extension_id:
        return value
    value = record.get("case_id")
    if isinstance(value, str) and value:
        return value
    return None


def is_report_record(record: dict[str, Any]) -> bool:
    if extension_id_from_record(record) is None:
        return False
    return any(
        key in record
        for key in (
            "artifact_path",
            "case_id",
            "conformance_tier",
            "correlation_id",
            "error",
            "failure_reason",
            "failures",
            "overall_status",
            "run_id",
            "schema",
            "set",
            "status",
            "tier",
        )
    )


def iter_json_records(data: Any, source: Path, json_path: str = "$") -> list[ReportRecord]:
    records: list[ReportRecord] = []
    if isinstance(data, dict):
        if is_report_record(data):
            records.append(ReportRecord(data, source, json_path=json_path))
        for key, value in data.items():
            records.extend(iter_json_records(value, source, f"{json_path}.{key}"))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            records.extend(iter_json_records(item, source, f"{json_path}[{index}]"))
    return records


def load_report_records(path: Path) -> tuple[list[ReportRecord], str | None]:
    if not path.is_file():
        return [], f"missing report: {repo_relative(path)}"

    if path.suffix == ".jsonl":
        records: list[ReportRecord] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return [], str(exc)
        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return [], f"{repo_relative(path)}:{line_number}: invalid JSONL: {exc}"
            if isinstance(event, dict) and is_report_record(event):
                records.append(ReportRecord(event, path, line=line_number))
        return records, None

    loaded = read_json(path)
    if loaded.error is not None:
        return [], f"{repo_relative(path)}: {loaded.error}"
    return iter_json_records(loaded.payload, path), None


def status_from_record(record: dict[str, Any]) -> str | None:
    for key in ("status", "overall_status"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def render_failure_item(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def failure_text_from_record(record: dict[str, Any]) -> str:
    for key in ("failure_reason", "error", "cause_detail", "message"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value

    failures = record.get("failures")
    if isinstance(failures, list) and failures:
        return "\n".join(render_failure_item(item) for item in failures)
    if isinstance(failures, str) and failures:
        return failures

    cause = record.get("cause_code")
    status = status_from_record(record)
    if isinstance(cause, str) and cause:
        return f"{status or 'status'}: {cause}"
    return f"{status or 'unknown failure'}"


def is_failure_record(record: dict[str, Any]) -> bool:
    status = (status_from_record(record) or "").strip().lower()
    if status in FAIL_STATUSES:
        return True
    failures = record.get("failures")
    if isinstance(failures, list) and bool(failures):
        return True
    if isinstance(failures, str) and bool(failures.strip()):
        return True
    return False


def sanitize_extension_id(extension_id: str) -> str:
    return extension_id.replace("/", "__")


def test_name_for_extension(extension_id: str) -> str:
    return "ext_" + extension_id.replace("/", "_").replace("-", "_")


def normalize_failure_text(text: str, repo_root: Path) -> str:
    normalized = text.strip().lower()
    if not normalized:
        return "unknown failure"
    repo_text = str(repo_root.resolve())
    normalized = normalized.replace(repo_text.lower(), "<repo>")
    normalized = re.sub(r"/[^\s)'\"`]+/tests/ext_conformance/artifacts/[^\s)'\"`]+", "<artifact>", normalized)
    normalized = re.sub(r"\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b", "<timestamp>", normalized)
    normalized = re.sub(r":\d+:\d+\b", ":<line>:<col>", normalized)
    normalized = re.sub(r":\d+\b", ":<line>", normalized)
    normalized = re.sub(r"\b\d+(?:\.\d+)?\s*ms\b", "<duration>", normalized)
    normalized = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def excerpt(text: str, limit: int = 220) -> str:
    one_line = " ".join(text.strip().split())
    if len(one_line) <= limit:
        return one_line
    return f"{one_line[: limit - 3]}..."


def load_manifest(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    loaded = read_json(path)
    if loaded.error is not None:
        return {}, loaded.error
    data = loaded.payload
    entries = data.get("extensions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return {}, "manifest root does not contain an extensions list"
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ext_id = entry.get("id")
        if isinstance(ext_id, str) and ext_id:
            result[ext_id] = entry
    return result, None


def load_inventory(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    loaded = read_json(path)
    if loaded.error is not None:
        return {}, loaded.error
    payload = loaded.payload
    entries = payload.get("extensions") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        return {}, "inventory root is not a list or object with extensions"
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ext_id = entry.get("id")
        if isinstance(ext_id, str) and ext_id:
            result[ext_id] = entry
    return result, None


def capabilities_for(meta: dict[str, Any]) -> dict[str, bool]:
    caps = meta.get("capabilities")
    if not isinstance(caps, dict):
        return {}
    return {str(key): bool(value) for key, value in caps.items() if isinstance(value, bool)}


def registrations_summary(meta: dict[str, Any]) -> dict[str, int]:
    registrations = meta.get("registrations")
    if not isinstance(registrations, dict):
        return {}
    summary: dict[str, int] = {}
    for key, value in registrations.items():
        if isinstance(value, list):
            summary[str(key)] = len(value)
        elif isinstance(value, int):
            summary[str(key)] = value
    return summary


def fixture_path_from_record(record: dict[str, Any], extension_id: str, repo_root: Path) -> Path:
    evidence = record.get("evidence")
    if isinstance(evidence, dict):
        fixture = evidence.get("fixture")
        if isinstance(fixture, str) and fixture:
            return resolve_path(Path(fixture), repo_root) or repo_root / fixture
    return repo_root / "tests" / "ext_conformance" / "fixtures" / f"{sanitize_extension_id(extension_id)}.json"


def fixture_summary(record: dict[str, Any], extension_id: str, repo_root: Path) -> dict[str, Any]:
    path = fixture_path_from_record(record, extension_id, repo_root)
    rel_path = repo_relative(path, repo_root)
    if not path.is_file():
        return {"path": rel_path, "exists": False, "schema": None, "scenario_count": 0}

    loaded = read_json(path)
    if loaded.error is not None or not isinstance(loaded.payload, dict):
        return {
            "path": rel_path,
            "exists": True,
            "schema": None,
            "scenario_count": 0,
            "error": loaded.error or "fixture root is not an object",
        }
    payload = loaded.payload
    scenarios = payload.get("scenarios")
    scenario_entries = scenarios if isinstance(scenarios, list) else []
    scenario_kinds = sorted(
        {
            scenario.get("kind")
            for scenario in scenario_entries
            if isinstance(scenario, dict) and isinstance(scenario.get("kind"), str)
        }
    )
    scenario_ids = [
        scenario.get("id")
        for scenario in scenario_entries[:10]
        if isinstance(scenario, dict) and isinstance(scenario.get("id"), str)
    ]
    return {
        "path": rel_path,
        "exists": True,
        "schema": payload.get("schema"),
        "scenario_count": len(scenario_entries),
        "scenario_ids": scenario_ids,
        "scenario_kinds": scenario_kinds,
    }


def load_baseline(path: Path, *, now: datetime, stale_days: int) -> dict[str, Any]:
    loaded = read_json(path)
    known_failures: dict[str, dict[str, Any]] = {}
    known_scenarios: dict[str, dict[str, Any]] = {}
    classification_counts: dict[str, int] = {}
    warnings: list[str] = []
    generated_at = None
    stale = False
    age_days = None
    schema = None

    if loaded.error is not None:
        return {
            "source": str(path),
            "schema": None,
            "available": False,
            "generated_at": None,
            "age_days": None,
            "stale": True,
            "stale_days": stale_days,
            "known_failure_ids": [],
            "known_scenario_ids": [],
            "known_failures": {},
            "warnings": [loaded.error],
        }

    payload = loaded.payload if isinstance(loaded.payload, dict) else {}
    schema = payload.get("schema")
    generated_at = payload.get("generated_at")
    generated_at_dt = parse_iso_datetime(generated_at)
    if generated_at_dt is None:
        warnings.append("baseline generated_at is missing or invalid")
        stale = True
    else:
        age_days = round((now - generated_at_dt).total_seconds() / 86400, 2)
        stale = age_days > stale_days
        if stale:
            warnings.append(
                f"{BASELINE_STALE_WARNING}: baseline age {age_days} days exceeds {stale_days} day threshold"
            )

    exception_policy = payload.get("exception_policy")
    if isinstance(exception_policy, dict):
        for entry in exception_policy.get("entries", []):
            if not isinstance(entry, dict):
                continue
            ext_id = entry.get("id")
            if isinstance(ext_id, str) and ext_id:
                known_failures[ext_id] = {
                    "source": "exception_policy",
                    "cause_code": entry.get("cause_code"),
                    "tracking_issue": entry.get("tracking_issue"),
                    "status": entry.get("status"),
                    "owner": entry.get("owner"),
                }

    classifications = payload.get("failure_classification")
    if isinstance(classifications, dict):
        for bucket_name, bucket in classifications.items():
            if not isinstance(bucket, dict):
                continue
            classification_counts[str(bucket_name)] = int(bucket.get("count") or 0)
            for ext_id in bucket.get("extensions", []):
                if isinstance(ext_id, str) and ext_id:
                    known_failures.setdefault(
                        ext_id,
                        {
                            "source": "failure_classification",
                            "cause_code": bucket_name,
                            "tracking_issue": None,
                            "status": "known",
                            "owner": None,
                        },
                    )
            for scenario_id in bucket.get("scenarios", []):
                if isinstance(scenario_id, str) and scenario_id:
                    known_scenarios.setdefault(
                        scenario_id,
                        {
                            "source": "failure_classification",
                            "cause_code": bucket_name,
                        },
                    )

    scenarios = payload.get("scenario_conformance")
    failures = scenarios.get("failures") if isinstance(scenarios, dict) else None
    if isinstance(failures, list):
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            scenario_id = failure.get("id")
            if isinstance(scenario_id, str) and scenario_id:
                known_scenarios.setdefault(
                    scenario_id,
                    {
                        "source": "scenario_conformance",
                        "cause_code": failure.get("cause"),
                    },
                )

    return {
        "source": str(path),
        "schema": schema,
        "available": True,
        "generated_at": generated_at,
        "age_days": age_days,
        "stale": stale,
        "stale_days": stale_days,
        "known_failure_ids": sorted(known_failures),
        "known_scenario_ids": sorted(known_scenarios),
        "known_failures": known_failures,
        "known_scenarios": known_scenarios,
        "failure_classification_counts": dict(sorted(classification_counts.items())),
        "warnings": warnings,
    }


def baseline_cause_for(
    extension_id: str,
    case_id: str | None,
    baseline: dict[str, Any],
    inventory_meta: dict[str, Any],
) -> str | None:
    known = baseline.get("known_failures", {})
    if isinstance(known, dict):
        entry = known.get(extension_id)
        if isinstance(entry, dict) and isinstance(entry.get("cause_code"), str):
            return entry["cause_code"]
    known_scenarios = baseline.get("known_scenarios", {})
    if isinstance(case_id, str) and isinstance(known_scenarios, dict):
        entry = known_scenarios.get(case_id)
        if isinstance(entry, dict) and isinstance(entry.get("cause_code"), str):
            return entry["cause_code"]
    cause = inventory_meta.get("cause_code")
    if isinstance(cause, str) and cause:
        return cause
    return None


def likely_fix_surface(text: str, meta: dict[str, Any], cause_code: str | None) -> str:
    cause = (cause_code or "").strip().lower()
    if cause == "test_fixture":
        return "test_fixture_or_manifest_fixture"
    if cause == "missing_npm_package":
        return "module_resolution_or_package_stub"
    if cause == "multi_file_dependency":
        return "module_resolution_or_package_layout"
    if cause == "policy_blocked":
        return "capability_policy_or_asset_packaging"
    if cause in {"mock_gap", "vcr_stub_gap"}:
        return "scenario_harness_mock_or_vcr_stub"

    lowered = text.lower()
    if "registertool" in lowered or "spec.name" in lowered or "schema" in lowered and "required" in lowered:
        return "extension_manifest_or_tool_schema"
    if "not a function" in lowered or "undefined" in lowered or "cannot read propert" in lowered:
        return "quickjs_node_shim_or_extension_api"
    if "cannot find module" in lowered or "module specifier" in lowered or "package" in lowered:
        return "module_resolution_or_package_stub"
    if "denied" in lowered or "permission" in lowered or "sandbox" in lowered or "capability" in lowered:
        return "capability_policy"

    caps = capabilities_for(meta)
    registrations = registrations_summary(meta)
    if caps.get("registers_providers") or registrations.get("providers", 0) > 0:
        return "provider_extension_runtime_api"
    if caps.get("uses_exec"):
        return "exec_hostcall_or_mock_runtime"
    return "extension_runtime"


def novelty_for(extension_id: str, case_id: str | None, baseline: dict[str, Any]) -> str:
    if not baseline.get("available"):
        return "baseline_unavailable"
    known = baseline.get("known_failures", {})
    if isinstance(known, dict) and extension_id in known:
        return "known_baseline_failure"
    known_scenarios = baseline.get("known_scenarios", {})
    if isinstance(case_id, str) and isinstance(known_scenarios, dict) and case_id in known_scenarios:
        return "known_baseline_failure"
    if baseline.get("stale"):
        return "new_or_untracked_failure_against_stale_baseline"
    return "new_or_untracked_failure"


def novelty_score(novelty: str) -> int:
    if novelty == "new_or_untracked_failure":
        return 42
    if novelty == "new_or_untracked_failure_against_stale_baseline":
        return 34
    if novelty == "baseline_unavailable":
        return 24
    return 5


def fix_surface_score(surface: str) -> int:
    scores = {
        "quickjs_node_shim_or_extension_api": 26,
        "provider_extension_runtime_api": 24,
        "extension_manifest_or_tool_schema": 20,
        "module_resolution_or_package_layout": 18,
        "module_resolution_or_package_stub": 18,
        "exec_hostcall_or_mock_runtime": 16,
        "capability_policy_or_asset_packaging": 14,
        "capability_policy": 14,
        "scenario_harness_mock_or_vcr_stub": 7,
        "test_fixture_or_manifest_fixture": 0,
    }
    return scores.get(surface, 12)


def source_tier(meta: dict[str, Any], inventory_meta: dict[str, Any], record: dict[str, Any]) -> str | None:
    for source in (record, meta, inventory_meta):
        value = source.get("source_tier") if isinstance(source, dict) else None
        if isinstance(value, str) and value:
            return value
        value = source.get("source") if isinstance(source, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def conformance_tier(meta: dict[str, Any], inventory_meta: dict[str, Any], record: dict[str, Any]) -> int | None:
    for source, key in ((record, "tier"), (record, "conformance_tier"), (meta, "conformance_tier"), (inventory_meta, "tier")):
        value = source.get(key) if isinstance(source, dict) else None
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def impact_score(
    extension_id: str,
    record: dict[str, Any],
    meta: dict[str, Any],
    inventory_meta: dict[str, Any],
    fix_surface: str,
) -> int:
    score = 0
    set_name = str(record.get("set") or "").lower()
    if set_name == "must_pass":
        score += 70
    elif set_name == "stretch":
        score += 25
    else:
        score += 35

    tier = conformance_tier(meta, inventory_meta, record)
    if tier is not None:
        if tier <= 1:
            score += 35
        elif tier == 2:
            score += 25
        elif tier == 3:
            score += 15
        elif tier == 4:
            score += 8
        else:
            score += 5

    src = (source_tier(meta, inventory_meta, record) or "").lower()
    if "official" in src:
        score += 25
    elif "npm" in src:
        score += 15
    elif "community" in src:
        score += 10
    elif "third-party" in src:
        score += 8

    caps = capabilities_for(meta)
    registrations = registrations_summary(meta)
    if caps.get("registers_providers") or registrations.get("providers", 0) > 0:
        score += 20
    if caps.get("registers_tools") or registrations.get("tools", 0) > 0:
        score += 10
    if caps.get("uses_exec"):
        score += 5

    if extension_id == "base_fixtures" or fix_surface == "test_fixture_or_manifest_fixture":
        score -= 65
    if fix_surface == "scenario_harness_mock_or_vcr_stub":
        score -= 35
    return max(0, min(score, 100))


def impact_band(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def occurrence_from_record(
    report_record: ReportRecord,
    *,
    repo_root: Path,
    manifest: dict[str, dict[str, Any]],
    inventory: dict[str, dict[str, Any]],
    baseline: dict[str, Any],
) -> dict[str, Any] | None:
    record = report_record.record
    if not is_failure_record(record):
        return None
    extension_id = extension_id_from_record(record)
    if extension_id is None:
        return None

    case_id = case_id_from_record(record, extension_id)
    manifest_meta = manifest.get(extension_id, {})
    inventory_meta = inventory.get(extension_id, {})
    merged_meta = {**inventory_meta, **manifest_meta}
    raw_failure = failure_text_from_record(record)
    normalized_failure = normalize_failure_text(raw_failure, repo_root)
    cause_code = baseline_cause_for(extension_id, case_id, baseline, inventory_meta)
    surface = likely_fix_surface(raw_failure, merged_meta, cause_code)
    novelty = novelty_for(extension_id, case_id, baseline)
    impact = impact_score(extension_id, record, merged_meta, inventory_meta, surface)
    signature_material = f"{surface}\n{normalized_failure}"
    signature_id = hashlib.sha256(signature_material.encode("utf-8")).hexdigest()[:16]

    return {
        "extension_id": extension_id,
        "case_id": case_id,
        "signature_id": signature_id,
        "signature_material": signature_material,
        "normalized_failure": normalized_failure,
        "failure_excerpt": excerpt(raw_failure),
        "status": status_from_record(record),
        "set": record.get("set"),
        "tier": conformance_tier(merged_meta, inventory_meta, record),
        "source_tier": source_tier(merged_meta, inventory_meta, record),
        "run_id": record.get("run_id"),
        "correlation_id": record.get("correlation_id"),
        "report_location": report_record.location,
        "report_path": repo_relative(report_record.source, repo_root),
        "artifact_path": record.get("artifact_path") or merged_meta.get("entry_path"),
        "fixture": fixture_summary(record, extension_id, repo_root),
        "capabilities": capabilities_for(merged_meta),
        "registrations": registrations_summary(merged_meta),
        "baseline_cause_code": cause_code,
        "regression_novelty": novelty,
        "likely_fix_surface": surface,
        "impact_score": impact,
        "impact": impact_band(impact),
    }


def group_occurrences(occurrences: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for occurrence in occurrences:
        groups.setdefault(str(occurrence["signature_id"]), []).append(occurrence)

    signatures: list[dict[str, Any]] = []
    for signature_id, items in groups.items():
        extension_ids = sorted({str(item["extension_id"]) for item in items})
        report_locations = sorted({str(item["report_location"]) for item in items})
        fix_surface = str(items[0]["likely_fix_surface"])
        novelty_counts: dict[str, int] = {}
        for item in items:
            novelty = str(item["regression_novelty"])
            novelty_counts[novelty] = novelty_counts.get(novelty, 0) + 1
        max_impact = max(int(item["impact_score"]) for item in items)
        max_novelty = max(novelty_score(str(item["regression_novelty"])) for item in items)
        rank_score = max_impact + max_novelty + fix_surface_score(fix_surface)
        example = sorted(
            items,
            key=lambda item: (
                -int(item["impact_score"]),
                -novelty_score(str(item["regression_novelty"])),
                str(item["extension_id"]),
            ),
        )[0]
        signatures.append(
            {
                "signature_id": signature_id,
                "rank_score": rank_score,
                "occurrence_count": len(items),
                "extension_count": len(extension_ids),
                "extension_ids": extension_ids,
                "likely_fix_surface": fix_surface,
                "impact": impact_band(max_impact),
                "impact_score": max_impact,
                "regression_novelty_counts": dict(sorted(novelty_counts.items())),
                "failure_signature": example["normalized_failure"],
                "failure_excerpt": example["failure_excerpt"],
                "sets": sorted({str(item["set"]) for item in items if item.get("set") is not None}),
                "tiers": sorted({int(item["tier"]) for item in items if isinstance(item.get("tier"), int)}),
                "source_tiers": sorted(
                    {str(item["source_tier"]) for item in items if item.get("source_tier") is not None}
                ),
                "report_locations": report_locations[:20],
                "examples": sorted(
                    items,
                    key=lambda item: (str(item["extension_id"]), str(item["report_location"])),
                )[:10],
            }
        )

    signatures.sort(
        key=lambda item: (
            -int(item["rank_score"]),
            -int(item["impact_score"]),
            item["signature_id"],
        )
    )
    for index, signature in enumerate(signatures, 1):
        signature["rank"] = index
        signature["bead_ready"] = bead_ready_fields(signature)
    return signatures


def command_for_extension(extension_id: str) -> str:
    test_name = test_name_for_extension(extension_id)
    return (
        "rch exec -- cargo test --test ext_conformance_generated "
        f"--features ext-conformance -- {test_name} --exact --nocapture --include-ignored"
    )


def bead_ready_fields(signature: dict[str, Any]) -> dict[str, Any]:
    extension_ids = [str(item) for item in signature.get("extension_ids", [])]
    surface = str(signature.get("likely_fix_surface"))
    novelty_counts = signature.get("regression_novelty_counts", {})
    has_new = any(str(key).startswith("new_or_untracked") for key in novelty_counts)
    priority = 1 if signature.get("impact") == "high" or has_new else 2
    if surface == "test_fixture_or_manifest_fixture":
        priority = 3
    title_count = f"{len(extension_ids)} extensions" if len(extension_ids) != 1 else extension_ids[0]
    title = f"Fix {surface} conformance failure for {title_count}"
    labels = ["extensions", "conformance", "triage", surface]
    labels.append("regression" if has_new else "known-baseline")
    commands = [command_for_extension(ext_id) for ext_id in extension_ids[:3]]
    body_lines = [
        f"Signature: {signature.get('failure_excerpt')}",
        f"Impact: {signature.get('impact')} (score {signature.get('impact_score')})",
        f"Regression novelty: {json.dumps(novelty_counts, sort_keys=True)}",
        f"Likely fix surface: {surface}",
        f"Current occurrences: {signature.get('occurrence_count')} across {len(extension_ids)} extension(s)",
        "Reproducer commands:",
        *[f"- {command}" for command in commands],
    ]
    return {
        "suggested_title": title,
        "suggested_priority": priority,
        "suggested_type": "bug" if has_new else "task",
        "suggested_labels": labels,
        "suggested_body": "\n".join(body_lines),
        "reproducer_commands": commands,
        "source_report_locations": signature.get("report_locations", []),
    }


def source_report_paths(args: argparse.Namespace, repo_root: Path) -> list[Path]:
    reports: list[Path] = []
    if not args.no_default_reports:
        reports.extend(DEFAULT_REPORTS)
    for report in args.report or []:
        resolved = resolve_path(report, repo_root)
        if resolved is not None:
            reports.append(resolved)
    deduped: list[Path] = []
    seen: set[str] = set()
    for report in reports:
        key = str(report.resolve()) if report.exists() else str(report)
        if key not in seen:
            seen.add(key)
            deduped.append(report)
    return deduped


def build_report(
    *,
    repo_root: Path,
    reports: list[Path],
    baseline_path: Path,
    manifest_path: Path,
    inventory_path: Path,
    now: datetime,
    stale_days: int,
) -> dict[str, Any]:
    manifest, manifest_error = load_manifest(manifest_path)
    inventory, inventory_error = load_inventory(inventory_path)
    baseline = load_baseline(baseline_path, now=now, stale_days=stale_days)

    load_warnings = []
    if manifest_error:
        load_warnings.append(f"manifest: {manifest_error}")
    if inventory_error:
        load_warnings.append(f"inventory: {inventory_error}")

    records: list[ReportRecord] = []
    report_inputs: list[dict[str, Any]] = []
    for report_path in reports:
        report_records, error = load_report_records(report_path)
        report_inputs.append(
            {
                "path": repo_relative(report_path, repo_root),
                "loaded_records": len(report_records),
                "error": error,
            }
        )
        if error:
            load_warnings.append(error)
        records.extend(report_records)

    occurrences = [
        occurrence
        for report_record in records
        if (
            occurrence := occurrence_from_record(
                report_record,
                repo_root=repo_root,
                manifest=manifest,
                inventory=inventory,
                baseline=baseline,
            )
        )
        is not None
    ]
    signatures = group_occurrences(occurrences)
    new_count = sum(
        1
        for occurrence in occurrences
        if str(occurrence["regression_novelty"]).startswith("new_or_untracked")
    )
    known_count = sum(
        1 for occurrence in occurrences if occurrence["regression_novelty"] == "known_baseline_failure"
    )
    status = "failures_found" if occurrences else "no_current_failures"
    if baseline.get("stale") and occurrences:
        status = "failures_found_baseline_stale"

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": iso_now(now),
        "status": status,
        "policy": POLICY,
        "source_root": str(repo_root),
        "source_files": {
            "baseline": repo_relative(baseline_path, repo_root),
            "manifest": repo_relative(manifest_path, repo_root),
            "inventory": repo_relative(inventory_path, repo_root),
            "reports": report_inputs,
        },
        "thresholds": {
            "baseline_stale_days": stale_days,
        },
        "summary": {
            "report_record_count": len(records),
            "failure_occurrence_count": len(occurrences),
            "collapsed_signature_count": len(signatures),
            "new_or_untracked_occurrence_count": new_count,
            "known_baseline_occurrence_count": known_count,
            "baseline_stale": bool(baseline.get("stale")),
        },
        "baseline": {
            key: value
            for key, value in baseline.items()
            if key not in {"known_failures", "known_scenarios"}
        },
        "warnings": sorted(set(load_warnings + baseline.get("warnings", []))),
        "failure_signatures": signatures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Extension Conformance Failure Triage",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Failure occurrences: `{summary['failure_occurrence_count']}`",
        f"- Collapsed signatures: `{summary['collapsed_signature_count']}`",
        f"- New/untracked occurrences: `{summary['new_or_untracked_occurrence_count']}`",
        f"- Known-baseline occurrences: `{summary['known_baseline_occurrence_count']}`",
        f"- Baseline stale: `{str(summary['baseline_stale']).lower()}`",
        "",
    ]
    warnings = report.get("warnings") or []
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    signatures = report.get("failure_signatures") or []
    if not signatures:
        lines.extend(["## Ranked Failures", "", "No current conformance failures found.", ""])
        return "\n".join(lines)

    lines.extend(["## Ranked Failures", ""])
    for signature in signatures:
        bead = signature["bead_ready"]
        lines.extend(
            [
                f"### {signature['rank']}. {signature['likely_fix_surface']}",
                "",
                f"- Signature: `{signature['signature_id']}`",
                f"- Impact: `{signature['impact']}` (score `{signature['impact_score']}`)",
                f"- Rank score: `{signature['rank_score']}`",
                f"- Extensions: `{', '.join(signature['extension_ids'])}`",
                f"- Occurrences: `{signature['occurrence_count']}`",
                f"- Novelty: `{json.dumps(signature['regression_novelty_counts'], sort_keys=True)}`",
                f"- Failure: {signature['failure_excerpt']}",
                f"- Bead title: {bead['suggested_title']}",
                "",
            ]
        )
        commands = bead.get("reproducer_commands") or []
        if commands:
            lines.append("```bash")
            lines.extend(commands[:2])
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def print_text_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(
        "status={status} failures={failures} signatures={signatures} new={new} known={known} "
        "baseline_stale={baseline_stale}".format(
            status=report["status"],
            failures=summary["failure_occurrence_count"],
            signatures=summary["collapsed_signature_count"],
            new=summary["new_or_untracked_occurrence_count"],
            known=summary["known_baseline_occurrence_count"],
            baseline_stale=str(summary["baseline_stale"]).lower(),
        )
    )
    for signature in report.get("failure_signatures", [])[:8]:
        print(
            "- rank={rank} score={score} surface={surface} impact={impact} extensions={extensions}: {failure}".format(
                rank=signature["rank"],
                score=signature["rank_score"],
                surface=signature["likely_fix_surface"],
                impact=signature["impact"],
                extensions=",".join(signature["extension_ids"]),
                failure=signature["failure_excerpt"],
            )
        )
    for warning in report.get("warnings", []):
        print(f"- warning={warning}")


def write_output(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build deterministic triage for extension conformance failures."
    )
    parser.add_argument("--report", action="append", type=Path, help="Additional report JSON/JSONL path")
    parser.add_argument(
        "--no-default-reports",
        action="store_true",
        help="Use only --report paths instead of the canonical report set",
    )
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--baseline-stale-days", type=int, default=DEFAULT_STALE_DAYS)
    parser.add_argument("--now", help="Override generated_at/staleness clock for deterministic tests")
    parser.add_argument("--out-json", type=Path, help="Write JSON report to this path")
    parser.add_argument("--out-md", type=Path, help="Write Markdown report to this path")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON stdout")
    parser.add_argument("--self-test", action="store_true", help="Run script self-tests")
    return parser.parse_args(argv)


def assert_condition(condition: bool, message: str, report: dict[str, Any] | None = None) -> None:
    if condition:
        return
    if report is not None:
        sys.stderr.write(json_dumps(report, pretty=True))
    raise AssertionError(message)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json_dumps(row, pretty=False) for row in rows), encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_dumps(payload, pretty=True), encoding="utf-8")


def run_self_test() -> int:
    now = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    with tempfile.TemporaryDirectory(prefix="pi_ext_triage_") as temp_dir:
        root = Path(temp_dir)
        report_path = root / "tests" / "ext_conformance" / "reports" / "gate" / "events.jsonl"
        baseline_path = root / "tests" / "ext_conformance" / "reports" / "conformance_baseline.json"
        manifest_path = root / "tests" / "ext_conformance" / "VALIDATED_MANIFEST.json"
        inventory_path = root / "tests" / "ext_conformance" / "reports" / "inventory.json"
        fixture_path = root / "tests" / "ext_conformance" / "fixtures" / "ext-new.json"

        write_jsonl(
            report_path,
            [
                {
                    "schema": "pi.ext.gate_event.v1",
                    "id": "ext-new",
                    "status": "fail",
                    "set": "must_pass",
                    "tier": 1,
                    "failure_reason": "TypeError: getClient is not a function at /tmp/a/tests/ext_conformance/artifacts/ext-new/index.ts:12:3",
                    "run_id": "run-1",
                },
                {
                    "schema": "pi.ext.gate_event.v1",
                    "id": "ext-new",
                    "status": "fail",
                    "set": "must_pass",
                    "tier": 1,
                    "failure_reason": "TypeError: getClient is not a function at /tmp/b/tests/ext_conformance/artifacts/ext-new/index.ts:99:7",
                    "run_id": "run-1",
                },
                {
                    "schema": "pi.ext.gate_event.v1",
                    "id": "ext-known",
                    "status": "fail",
                    "set": "stretch",
                    "tier": 3,
                    "failure_reason": "Cannot find module 'openai'",
                },
                {
                    "schema": "pi.ext.gate_event.v1",
                    "id": "base_fixtures",
                    "status": "fail",
                    "set": "stretch",
                    "tier": 3,
                    "failure_reason": "registerTool: spec.name is required for tool",
                },
                {
                    "schema": "pi.ext.gate_event.v1",
                    "id": "ext-pass",
                    "status": "pass",
                    "set": "must_pass",
                    "tier": 1,
                },
            ],
        )
        write_json(
            baseline_path,
            {
                "schema": "pi.ext.conformance_baseline.v2",
                "generated_at": "2026-01-01T00:00:00Z",
                "failure_classification": {
                    "missing_npm_package": {
                        "count": 1,
                        "extensions": ["ext-known"],
                    },
                    "test_fixture": {
                        "count": 1,
                        "extensions": ["base_fixtures"],
                    },
                },
                "exception_policy": {
                    "entries": [
                        {
                            "id": "base_fixtures",
                            "cause_code": "test_fixture",
                            "tracking_issue": "bd-fixture",
                            "status": "approved",
                            "owner": "pi-conformance-team",
                        }
                    ]
                },
            },
        )
        write_json(
            manifest_path,
            {
                "extensions": [
                    {
                        "id": "ext-new",
                        "source_tier": "official-pi-mono",
                        "conformance_tier": 1,
                        "entry_path": "ext-new/index.ts",
                        "capabilities": {"registers_providers": True, "registers_tools": True},
                        "registrations": {"providers": ["new"], "tools": ["ask"]},
                    },
                    {
                        "id": "ext-known",
                        "source_tier": "npm-registry",
                        "conformance_tier": 3,
                        "capabilities": {"has_npm_deps": True},
                    },
                    {
                        "id": "base_fixtures",
                        "source_tier": "official-pi-mono",
                        "conformance_tier": 3,
                    },
                ]
            },
        )
        write_json(
            inventory_path,
            [
                {"id": "ext-new", "tier": 1, "status": "PASS"},
                {"id": "ext-known", "tier": 3, "status": "FAIL", "cause_code": "missing_npm_package"},
                {"id": "base_fixtures", "tier": 3, "status": "FAIL", "cause_code": "test_fixture"},
            ],
        )
        write_json(
            fixture_path,
            {
                "schema": "pi.ext.scenario_fixture.v1",
                "scenarios": [{"id": "scenario-1", "kind": "smoke"}],
            },
        )

        report = build_report(
            repo_root=root,
            reports=[report_path],
            baseline_path=baseline_path,
            manifest_path=manifest_path,
            inventory_path=inventory_path,
            now=now,
            stale_days=30,
        )
        assert_condition(report["summary"]["failure_occurrence_count"] == 4, "failure occurrence count", report)
        assert_condition(report["summary"]["collapsed_signature_count"] == 3, "duplicate signatures collapsed", report)
        assert_condition(report["summary"]["baseline_stale"] is True, "stale baseline detected", report)
        signatures = report["failure_signatures"]
        assert_condition(signatures[0]["extension_ids"] == ["ext-new"], "severity ordering puts new must-pass first", report)
        assert_condition(signatures[0]["occurrence_count"] == 2, "duplicate occurrence retained in group", report)
        bead = signatures[0]["bead_ready"]
        assert_condition("suggested_title" in bead, "bead title present", report)
        assert_condition("reproducer_commands" in bead and bead["reproducer_commands"], "bead repro command present", report)
        assert_condition("regression" in bead["suggested_labels"], "bead labels include regression", report)
        markdown = render_markdown(report)
        assert_condition("Extension Conformance Failure Triage" in markdown, "markdown title present", report)

        pass_report_path = root / "pass_events.jsonl"
        write_jsonl(
            pass_report_path,
            [{"schema": "pi.ext.gate_event.v1", "id": "ext-pass", "status": "pass"}],
        )
        no_fail_report = build_report(
            repo_root=root,
            reports=[pass_report_path],
            baseline_path=baseline_path,
            manifest_path=manifest_path,
            inventory_path=inventory_path,
            now=now,
            stale_days=30,
        )
        assert_condition(no_fail_report["status"] == "no_current_failures", "no-failure status", no_fail_report)

    print("SELF-TEST PASS: summarize_ext_conformance_failures")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    repo_root = REPO_ROOT
    now = parse_iso_datetime(args.now) if args.now else utc_now()
    if now is None:
        print(f"ERROR: invalid --now value: {args.now}", file=sys.stderr)
        return 2

    report = build_report(
        repo_root=repo_root,
        reports=source_report_paths(args, repo_root),
        baseline_path=resolve_path(args.baseline, repo_root) or args.baseline,
        manifest_path=resolve_path(args.manifest, repo_root) or args.manifest,
        inventory_path=resolve_path(args.inventory, repo_root) or args.inventory,
        now=now,
        stale_days=args.baseline_stale_days,
    )

    if args.out_json:
        write_output(args.out_json, json_dumps(report, pretty=True))
    if args.out_md:
        write_output(args.out_md, render_markdown(report) + "\n")

    if args.format == "json":
        sys.stdout.write(json_dumps(report, pretty=args.pretty))
    elif args.format == "markdown":
        print(render_markdown(report))
    else:
        print_text_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
