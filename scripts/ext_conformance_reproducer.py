#!/usr/bin/env python3
"""Build a focused extension conformance reproducer from JSON/JSONL reports."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "ext_conformance" / "VALIDATED_MANIFEST.json"
DEFAULT_OUTPUT_DIR = (
    REPO_ROOT / "tests" / "ext_conformance" / "reports" / "reproducers"
)
GENERATED_TESTS = REPO_ROOT / "tests" / "ext_conformance_generated.rs"
SCHEMA = "pi.ext.conformance_reproducer.v1"
REPORT_RECORD_KEYS = {
    "artifact_path",
    "conformance_tier",
    "correlation_id",
    "failure_reason",
    "failures",
    "overall_status",
    "run_id",
    "schema",
    "set",
    "status",
    "tier",
}


class ReproducerError(RuntimeError):
    """User-correctable reproducer input error."""


@dataclass(frozen=True)
class ReportRecord:
    record: dict[str, Any]
    source: Path
    line: int | None = None
    json_path: str | None = None

    @property
    def extension_id(self) -> str | None:
        return extension_id_from_record(self.record)

    @property
    def location(self) -> str:
        if self.line is not None:
            return f"{self.source}:{self.line}"
        if self.json_path:
            return f"{self.source}:{self.json_path}"
        return str(self.source)


def repo_relative(path: Path | str | None) -> str | None:
    if path is None:
        return None
    raw = Path(path)
    try:
        return raw.resolve().relative_to(REPO_ROOT).as_posix()
    except (OSError, ValueError):
        return raw.as_posix()


def resolve_repo_path(path: str | Path | None) -> Path | None:
    if path is None:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return REPO_ROOT / candidate


def sanitize_extension_id(extension_id: str) -> str:
    return extension_id.replace("/", "__")


def test_name_for_extension(extension_id: str) -> str:
    return "ext_" + extension_id.replace("/", "_").replace("-", "_")


def extension_id_from_record(record: dict[str, Any]) -> str | None:
    for key in ("extension_id", "id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def is_report_record(record: dict[str, Any]) -> bool:
    return extension_id_from_record(record) is not None and any(
        key in record for key in REPORT_RECORD_KEYS
    )


def load_json(path: Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ReproducerError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReproducerError(f"invalid JSON in {label} {path}: {exc}") from exc


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    data = load_json(path, "manifest")
    extensions = data.get("extensions") if isinstance(data, dict) else None
    if not isinstance(extensions, list):
        raise ReproducerError(f"invalid manifest {path}: expected extensions list")

    by_id: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for entry in extensions:
        if not isinstance(entry, dict):
            continue
        ext_id = entry.get("id")
        if not isinstance(ext_id, str) or not ext_id:
            continue
        if ext_id in by_id:
            duplicates.append(ext_id)
        by_id[ext_id] = entry

    if duplicates:
        joined = ", ".join(sorted(set(duplicates)))
        raise ReproducerError(f"manifest has duplicate extension ids: {joined}")
    return by_id


def iter_json_records(data: Any, source: Path, json_path: str = "$") -> list[ReportRecord]:
    records: list[ReportRecord] = []
    if isinstance(data, dict):
        if is_report_record(data):
            records.append(ReportRecord(data, source, json_path=json_path))
        for key, value in data.items():
            child_path = f"{json_path}.{key}"
            records.extend(iter_json_records(value, source, child_path))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            records.extend(iter_json_records(item, source, f"{json_path}[{idx}]"))
    return records


def load_report(path: Path) -> list[ReportRecord]:
    if not path.is_file():
        raise ReproducerError(f"missing report: {path}")

    if path.suffix == ".jsonl":
        records: list[ReportRecord] = []
        with path.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ReproducerError(
                        f"invalid JSONL in report {path}:{line_no}: {exc}"
                    ) from exc
                if isinstance(event, dict) and is_report_record(event):
                    records.append(ReportRecord(event, path, line=line_no))
        return records

    data = load_json(path, "report")
    return iter_json_records(data, path)


def select_report_record(extension_id: str, records: list[ReportRecord]) -> ReportRecord:
    matches = [record for record in records if record.extension_id == extension_id]
    if not matches:
        known = sorted({record.extension_id for record in records if record.extension_id})
        sample = ", ".join(known[:12])
        suffix = f"; known ids include: {sample}" if sample else ""
        raise ReproducerError(f"extension id not found in report: {extension_id}{suffix}")
    if len(matches) > 1:
        locations = ", ".join(match.location for match in matches)
        raise ReproducerError(
            f"multiple records found for extension id {extension_id!r}: {locations}"
        )
    return matches[0]


def first_string(values: list[Any]) -> str | None:
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None


def failure_text_from_record(record: dict[str, Any]) -> str | None:
    reason = record.get("failure_reason")
    if isinstance(reason, str) and reason:
        return reason

    failures = record.get("failures")
    if isinstance(failures, list) and failures:
        rendered = []
        for failure in failures:
            if isinstance(failure, str):
                rendered.append(failure)
            elif isinstance(failure, dict):
                rendered.append(json.dumps(failure, sort_keys=True))
            else:
                rendered.append(str(failure))
        return "\n".join(rendered)

    if isinstance(failures, str) and failures:
        return failures
    return None


def status_from_record(record: dict[str, Any]) -> str | None:
    return first_string([record.get("status"), record.get("overall_status")])


def report_kind(record: dict[str, Any]) -> str:
    schema = record.get("schema")
    if schema == "pi.ext.gate_event.v1":
        return "gate_event"
    if schema == "pi.ext.conformance_report.v2":
        return "conformance_report"
    if schema == "pi.ext.conformance_result.v1":
        return "conformance_result"
    if isinstance(schema, str) and schema:
        return schema
    return "unknown"


def artifact_from_failure_text(text: str | None) -> str | None:
    if not text:
        return None
    match = re.search(r"(/[^)\s]+tests/ext_conformance/artifacts/[^)\s]+)", text)
    if not match:
        return None
    raw_path = re.sub(r":\d+(?::\d+)?$", "", match.group(1))
    return repo_relative(Path(raw_path))


def artifact_paths(
    record: dict[str, Any], manifest_entry: dict[str, Any] | None, failure_text: str | None
) -> dict[str, str | None]:
    from_report = first_string([record.get("artifact_path")])
    from_failure = artifact_from_failure_text(failure_text)

    from_manifest = None
    if manifest_entry:
        entry_path = manifest_entry.get("entry_path")
        if isinstance(entry_path, str) and entry_path:
            from_manifest = (
                Path("tests") / "ext_conformance" / "artifacts" / entry_path
            ).as_posix()

    return {
        "selected": from_report or from_failure or from_manifest,
        "from_report": from_report,
        "from_failure_text": from_failure,
        "from_manifest": from_manifest,
    }


def fixture_path_from_record(record: dict[str, Any], extension_id: str) -> str | None:
    evidence = record.get("evidence")
    if isinstance(evidence, dict):
        fixture = evidence.get("fixture")
        if isinstance(fixture, str) and fixture:
            return fixture

    candidate = (
        Path("tests")
        / "ext_conformance"
        / "fixtures"
        / f"{sanitize_extension_id(extension_id)}.json"
    )
    if (REPO_ROOT / candidate).is_file():
        return candidate.as_posix()
    return None


def summarize_fixture(path_text: str | None) -> dict[str, Any]:
    path = resolve_repo_path(path_text)
    if path is None:
        return {"path": None, "exists": False, "metadata": None}

    rel_path = repo_relative(path)
    if not path.is_file():
        return {"path": rel_path, "exists": False, "metadata": None}

    data = load_json(path, "fixture")
    metadata: dict[str, Any] = {}
    if isinstance(data, dict):
        extension = data.get("extension")
        if isinstance(extension, dict):
            metadata["extension_id"] = extension.get("id")
            metadata["source"] = extension.get("source")
            metadata["checksum"] = extension.get("checksum")
        metadata["schema"] = data.get("schema")
        legacy = data.get("legacy")
        if isinstance(legacy, dict):
            metadata["legacy"] = {
                key: legacy.get(key)
                for key in ("pi_mono_head", "node_version", "npm_version")
                if key in legacy
            }
        scenarios = data.get("scenarios")
        if isinstance(scenarios, list):
            metadata["scenario_count"] = len(scenarios)
            metadata["scenario_ids"] = [
                scenario.get("id")
                for scenario in scenarios[:10]
                if isinstance(scenario, dict) and isinstance(scenario.get("id"), str)
            ]
            metadata["scenario_kinds"] = sorted(
                {
                    scenario.get("kind")
                    for scenario in scenarios
                    if isinstance(scenario, dict) and isinstance(scenario.get("kind"), str)
                }
            )

    return {"path": rel_path, "exists": True, "metadata": metadata}


def ignored_generated_tests() -> set[str]:
    if not GENERATED_TESTS.is_file():
        return set()
    source = GENERATED_TESTS.read_text(encoding="utf-8")
    ignored: set[str] = set()
    pattern = re.compile(
        r"conformance_test!\(\s*(ext_[A-Za-z0-9_]+)\s*,\s*\"([^\"]+)\"\s*,\s*ignore\s*\)"
    )
    for _test_name, ext_id in pattern.findall(source):
        ignored.add(ext_id)
    return ignored


def build_commands(extension_id: str, include_ignored: bool) -> dict[str, Any]:
    test_name = test_name_for_extension(extension_id)
    cargo_command = [
        "cargo",
        "test",
        "--test",
        "ext_conformance_generated",
        "--features",
        "ext-conformance",
        "--",
        test_name,
        "--exact",
        "--nocapture",
    ]
    if include_ignored:
        cargo_command.append("--include-ignored")

    rch_command = ["rch", "exec", "--", *cargo_command]
    return {
        "test_name": test_name,
        "include_ignored": include_ignored,
        "cargo": cargo_command,
        "cargo_display": " ".join(cargo_command),
        "rch": rch_command,
        "rch_display": " ".join(rch_command),
    }


def default_cargo_env() -> dict[str, str]:
    user = os.environ.get("USER", "agent")
    base = Path("/data/tmp/pi_agent_rust_cargo") / user
    return {
        "CARGO_TARGET_DIR": str(base / "target"),
        "TMPDIR": str(base / "tmp"),
    }


def run_command(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    env = os.environ.copy()
    for key, value in default_cargo_env().items():
        env.setdefault(key, value)
    Path(env["CARGO_TARGET_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "ran": True,
            "timed_out": False,
            "returncode": result.returncode,
            "stdout_tail": tail_lines(result.stdout),
            "stderr_tail": tail_lines(result.stderr),
            "env": {key: env[key] for key in ("CARGO_TARGET_DIR", "TMPDIR")},
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ran": True,
            "timed_out": True,
            "returncode": 124,
            "stdout_tail": tail_lines(exc.stdout or ""),
            "stderr_tail": tail_lines(exc.stderr or ""),
            "env": {key: env[key] for key in ("CARGO_TARGET_DIR", "TMPDIR")},
        }


def tail_lines(text: str, limit: int = 80) -> str:
    lines = text.splitlines()
    if len(lines) <= limit:
        return text
    return "\n".join(lines[-limit:])


def build_reproducer(
    extension_id: str | None,
    report_path: Path | None,
    manifest_path: Path,
    output_dir: Path,
    out_json: Path | None,
) -> dict[str, Any]:
    if not extension_id:
        raise ReproducerError("missing --extension-id")
    if not report_path:
        raise ReproducerError("missing --report")

    records = load_report(report_path)
    match = select_report_record(extension_id, records)
    manifest = load_manifest(manifest_path)
    manifest_entry = manifest.get(extension_id)
    record = match.record
    failure_text = failure_text_from_record(record)
    fixture_path = fixture_path_from_record(record, extension_id)
    ignored = extension_id in ignored_generated_tests()
    commands = build_commands(extension_id, ignored)
    output_path = out_json or output_dir / f"{sanitize_extension_id(extension_id)}.reproducer.json"

    plan = {
        "schema": SCHEMA,
        "extension_id": extension_id,
        "report": {
            "path": repo_relative(report_path),
            "kind": report_kind(record),
            "record_location": match.location,
            "match_count": 1,
            "status": status_from_record(record),
            "set": record.get("set"),
            "tier": record.get("tier") or record.get("conformance_tier"),
            "run_id": record.get("run_id"),
            "correlation_id": record.get("correlation_id"),
        },
        "artifact": artifact_paths(record, manifest_entry, failure_text),
        "fixture": summarize_fixture(fixture_path),
        "failure_text": failure_text,
        "manifest_entry": {
            "found": manifest_entry is not None,
            "entry_path": manifest_entry.get("entry_path") if manifest_entry else None,
            "source_tier": manifest_entry.get("source_tier") if manifest_entry else None,
            "conformance_tier": manifest_entry.get("conformance_tier")
            if manifest_entry
            else None,
            "registrations": manifest_entry.get("registrations") if manifest_entry else None,
        },
        "command": commands,
        "recommended_env": default_cargo_env(),
        "output_path": repo_relative(output_path),
        "wrote_output": False,
        "run": {"ran": False},
    }
    return plan


def write_output(plan: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plan["wrote_output"] = True
    output_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_text(plan: dict[str, Any]) -> str:
    failure = plan.get("failure_text") or "none"
    first_failure_line = str(failure).splitlines()[0] if failure else "none"
    fixture = plan.get("fixture", {})
    artifact = plan.get("artifact", {})
    command = plan.get("command", {})
    report = plan.get("report", {})
    return "\n".join(
        [
            f"Extension: {plan['extension_id']}",
            f"Report: {report.get('path')} ({report.get('kind')})",
            f"Status: {report.get('status')}",
            f"Artifact: {artifact.get('selected')}",
            f"Fixture: {fixture.get('path')} (exists={fixture.get('exists')})",
            f"Failure: {first_failure_line}",
            f"Command: {command.get('cargo_display')}",
            f"RCH: {command.get('rch_display')}",
            f"Output: {plan.get('output_path')} (written={plan.get('wrote_output')})",
        ]
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a one-extension conformance reproducer from event reports."
    )
    parser.add_argument("--extension-id", help="Extension id to reproduce")
    parser.add_argument("--report", type=Path, help="conformance_events or gate events JSONL/JSON")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--out-json", type=Path, help="Write the reproducer JSON to this path")
    parser.add_argument("--write", action="store_true", help="Write JSON to the output path")
    parser.add_argument("--run", action="store_true", help="Run the focused command")
    parser.add_argument(
        "--use-rch",
        action="store_true",
        help="When --run is set, run through rch exec -- cargo ...",
    )
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--self-test", action="store_true", help="Run script self-tests")
    return parser.parse_args(argv)


def run_self_tests() -> int:
    failures: list[str] = []

    def check(name: str, fn: Any) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - self-test reports all failures.
            failures.append(f"{name}: {exc}")

    def missing_extension_id() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "events.jsonl"
            report.write_text(
                json.dumps({"schema": "pi.ext.gate_event.v1", "id": "x", "status": "fail"})
                + "\n",
                encoding="utf-8",
            )
            try:
                build_reproducer(None, report, DEFAULT_MANIFEST, Path(tmp), None)
            except ReproducerError as exc:
                assert "missing --extension-id" in str(exc)
            else:
                raise AssertionError("expected missing extension id error")

    def duplicate_extension_id() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            report = Path(tmp) / "events.jsonl"
            manifest.write_text(
                json.dumps({"extensions": [{"id": "dupe", "entry_path": "dupe/index.ts"}]}),
                encoding="utf-8",
            )
            report.write_text(
                "\n".join(
                    [
                        json.dumps({"id": "dupe", "status": "fail"}),
                        json.dumps({"id": "dupe", "status": "fail"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            try:
                build_reproducer("dupe", report, manifest, Path(tmp), None)
            except ReproducerError as exc:
                assert "multiple records" in str(exc)
            else:
                raise AssertionError("expected duplicate extension id error")

    def real_fixture_failure() -> None:
        report = (
            REPO_ROOT
            / "tests"
            / "ext_conformance"
            / "reports"
            / "gate"
            / "must_pass_events.jsonl"
        )
        plan = build_reproducer(
            "npm/pi-multicodex", report, DEFAULT_MANIFEST, DEFAULT_OUTPUT_DIR, None
        )
        assert plan["report"]["status"] == "fail"
        assert "not a function" in plan["failure_text"]
        assert plan["artifact"]["selected"].endswith("npm/pi-multicodex/index.ts")
        assert plan["fixture"]["exists"] is True
        assert plan["fixture"]["metadata"]["scenario_count"] > 0
        assert "ext_npm_pi_multicodex" in plan["command"]["cargo_display"]

    check("missing_extension_id", missing_extension_id)
    check("duplicate_extension_id", duplicate_extension_id)
    check("real_fixture_failure", real_fixture_failure)

    if failures:
        for failure in failures:
            print(f"SELF-TEST FAIL: {failure}", file=sys.stderr)
        return 1
    print("SELF-TEST PASS: ext_conformance_reproducer")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()

    try:
        plan = build_reproducer(
            args.extension_id,
            args.report,
            args.manifest,
            args.output_dir,
            args.out_json,
        )

        output_path = args.out_json or args.output_dir / (
            f"{sanitize_extension_id(args.extension_id)}.reproducer.json"
        )

        if args.run:
            command = plan["command"]["rch"] if args.use_rch else plan["command"]["cargo"]
            plan["run"] = run_command(command, args.timeout_seconds)

        if args.write or args.out_json:
            write_output(plan, output_path)

        if args.format == "json":
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            print(render_text(plan))

        if args.run:
            return int(plan["run"].get("returncode", 1))
        return 0
    except ReproducerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
