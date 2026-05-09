#!/usr/bin/env python3
"""Build deterministic perf artifact staging manifests."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from preflight_budget_inputs import (
    DEFAULT_MAX_ARTIFACT_AGE_HOURS,
    EXTENSION_BLOCKER_BEAD,
    ArtifactGroup,
    artifact_groups,
    file_age_hours,
    iso_now,
    read_json,
    resolve_target_dir,
    sha256_file,
)


STAGING_SCHEMA = "pi.perf.artifact_staging_manifest.v1"
STAGING_ENTRY_SCHEMA = "pi.perf.artifact_staging_entry.v1"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def artifact_schema(path: Path) -> str | None:
    if path.suffix == ".json":
        payload = read_json(path)
        value = payload.get("schema") if payload else None
        return value if isinstance(value, str) else None
    if path.suffix == ".jsonl":
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    payload = json.loads(line)
                    if isinstance(payload, dict) and isinstance(payload.get("schema"), str):
                        return payload["schema"]
                    return None
        except (OSError, json.JSONDecodeError):
            return None
    return None


def mtime_utc(path: Path) -> str | None:
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None
    return modified.isoformat().replace("+00:00", "Z")


def remote_source_path(
    candidate: Path, target_dir: Path, remote_target_dir: Path | None
) -> tuple[str, bool]:
    if remote_target_dir is None:
        return str(candidate), True
    try:
        relative = candidate.resolve().relative_to(target_dir.resolve())
    except ValueError:
        return str(candidate), False
    return str(remote_target_dir / relative), False


def staged_report_path(
    candidate: Path, repo_root: Path, local_results_dir: Path | None
) -> Path | None:
    if local_results_dir is None:
        return None
    reports_root = repo_root / "tests/perf/reports"
    try:
        relative = candidate.resolve().relative_to(reports_root.resolve())
    except ValueError:
        return None
    return local_results_dir / "perf_reports" / relative


def artifact_entry(
    group: ArtifactGroup,
    candidate: Path,
    repo_root: Path,
    target_dir: Path,
    local_results_dir: Path | None,
    remote_target_dir: Path | None,
    max_age_hours: float,
    now: datetime,
    runner_mode: str,
) -> dict[str, Any]:
    age = file_age_hours(candidate, now)
    exists = candidate.is_file()
    is_fresh = exists and age is not None and age <= max_age_hours
    status = "present" if is_fresh else "stale" if exists else "missing"
    retrieval_status = {
        "present": "retrieved",
        "stale": "stale_after_run",
        "missing": "missing_after_run",
    }[status]
    source_path, inferred_remote_source = remote_source_path(candidate, target_dir, remote_target_dir)
    staged_path = staged_report_path(candidate, repo_root, local_results_dir)
    staged_path_str = str(staged_path) if staged_path is not None and staged_path.is_file() else None

    try:
        size_bytes = candidate.stat().st_size if exists else None
    except OSError:
        size_bytes = None

    return {
        "schema": STAGING_ENTRY_SCHEMA,
        "contract_id": group.contract_id,
        "budget_names": list(group.budget_names),
        "required": True,
        "status": status,
        "retrieval_status": retrieval_status,
        "reason": group.reason,
        "remote_source_path": source_path,
        "remote_source_path_inferred": inferred_remote_source,
        "source_path": str(candidate),
        "local_retrieved_path": str(candidate) if exists else None,
        "local_staged_path": staged_path_str,
        "size_bytes": size_bytes,
        "mtime_utc": mtime_utc(candidate) if exists else None,
        "age_hours": age,
        "max_age_hours": max_age_hours,
        "sha256": sha256_file(candidate) if exists else None,
        "artifact_schema": artifact_schema(candidate) if exists else None,
        "runner_mode": runner_mode,
        "suggested_commands": list(group.suggested_commands),
        "blocker": group.blocker,
    }


def build_staging_manifest(
    repo_root: Path,
    target_dir: Path,
    local_results_dir: Path | None,
    remote_target_dir: Path | None,
    max_age_hours: float,
    now: datetime,
    runner_mode: str,
) -> dict[str, Any]:
    groups = artifact_groups(repo_root, target_dir)
    entries: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    present_required = 0
    stale_required = 0
    missing_required = 0

    for group in groups:
        group_entries = [
            artifact_entry(
                group=group,
                candidate=candidate,
                repo_root=repo_root,
                target_dir=target_dir,
                local_results_dir=local_results_dir,
                remote_target_dir=remote_target_dir,
                max_age_hours=max_age_hours,
                now=now,
                runner_mode=runner_mode,
            )
            for candidate in group.candidates
        ]
        entries.extend(group_entries)
        has_present = any(entry["status"] == "present" for entry in group_entries)
        has_stale = any(entry["status"] == "stale" for entry in group_entries)
        group_status = "present" if has_present else "stale" if has_stale else "missing"
        if group_status == "present":
            present_required += 1
        elif group_status == "stale":
            stale_required += 1
        else:
            missing_required += 1
        if group_status != "present":
            blockers.append(
                {
                    "contract_id": group.contract_id,
                    "budget_names": list(group.budget_names),
                    "status": group_status,
                    "reason": group.reason,
                    "expected_paths": [str(path) for path in group.expected_outputs],
                    "candidate_paths": [str(path) for path in group.candidates],
                    "suggested_commands": list(group.suggested_commands),
                    "blocker": group.blocker,
                }
            )

    status = "ready" if missing_required == 0 and stale_required == 0 else "blocked"
    return {
        "schema": STAGING_SCHEMA,
        "generated_at": iso_now(),
        "repo_root": str(repo_root),
        "cargo_target_dir": str(target_dir),
        "remote_target_dir": str(remote_target_dir) if remote_target_dir is not None else None,
        "remote_source_path_mode": "explicit" if remote_target_dir is not None else "inferred_from_local_target",
        "local_results_dir": str(local_results_dir) if local_results_dir is not None else None,
        "max_artifact_age_hours": max_age_hours,
        "runner_mode": runner_mode,
        "summary": {
            "status": status,
            "required_contract_count": len(groups),
            "present_required_count": present_required,
            "stale_required_count": stale_required,
            "missing_required_count": missing_required,
            "entry_count": len(entries),
        },
        "entries": entries,
        "blockers": blockers,
        "safety_notes": [
            "Do not refresh tests/perf/reports/budget_summary.json while this manifest status is blocked.",
            "For RCH runs, remote_source_path is explicit only when PERF_REMOTE_TARGET_DIR is provided; "
            "otherwise it records the local post-RCH source path.",
        ],
    }


def write_fixture(root: Path, include_policy: bool) -> None:
    (root / "tests/perf/reports").mkdir(parents=True)
    (root / "target/criterion/ext_load_init/load_init_cold/hello/new").mkdir(parents=True)
    (root / "target/criterion/ext_protocol/parse_and_validate/log/new").mkdir(parents=True)
    (root / "target/perf/perf").mkdir(parents=True)
    (root / "target/release").mkdir(parents=True)
    (root / "target/perf/results").mkdir(parents=True)
    if include_policy:
        (root / "target/criterion/ext_policy/evaluate/safe/new").mkdir(parents=True)

    estimate_paths = [
        root / "target/criterion/startup/version/warm/new/estimates.json",
        root / "target/criterion/ext_load_init/load_init_cold/hello/new/estimates.json",
        root / "target/criterion/ext_protocol/parse_and_validate/log/new/estimates.json",
    ]
    if include_policy:
        estimate_paths.append(root / "target/criterion/ext_policy/evaluate/safe/new/estimates.json")
    for path in estimate_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"mean":{"point_estimate":1000.0}}\n', encoding="utf-8")

    (root / "target/perf/perf/pijs_workload_perf.jsonl").write_text(
        '{"schema":"pi.perf.workload.v1","tool_calls_per_iteration":1}\n',
        encoding="utf-8",
    )
    (root / "target/release/pi").write_bytes(b"binary")
    (root / "tests/perf/reports/extension_benchmark_stratification.json").write_text(
        '{"schema":"pi.perf.extension_benchmark_stratification.v1"}',
        encoding="utf-8",
    )
    (root / "target/perf/results/phase1_matrix_validation.json").write_text(
        '{"schema":"pi.perf.phase1_matrix_validation.v1"}',
        encoding="utf-8",
    )


def run_self_test() -> int:
    ok_root = Path(tempfile.mkdtemp(prefix="pi-perf-staging-ok-"))
    write_fixture(ok_root, include_policy=True)
    ok_manifest = build_staging_manifest(
        repo_root=ok_root,
        target_dir=ok_root / "target",
        local_results_dir=ok_root / "run/results",
        remote_target_dir=Path("/remote/pi-agent-target"),
        max_age_hours=24.0,
        now=utc_now(),
        runner_mode="rch",
    )
    assert ok_manifest["summary"]["status"] == "ready", ok_manifest
    policy_entries = [
        entry
        for entry in ok_manifest["entries"]
        if entry["contract_id"] == "extension_criterion_policy"
        and entry["status"] == "present"
    ]
    assert policy_entries, ok_manifest
    assert (
        policy_entries[0]["remote_source_path"]
        == "/remote/pi-agent-target/criterion/ext_policy/evaluate/safe/new/estimates.json"
    ), policy_entries[0]
    assert policy_entries[0]["retrieval_status"] == "retrieved", policy_entries[0]

    blocked_root = Path(tempfile.mkdtemp(prefix="pi-perf-staging-blocked-"))
    write_fixture(blocked_root, include_policy=False)
    blocked_manifest = build_staging_manifest(
        repo_root=blocked_root,
        target_dir=blocked_root / "target",
        local_results_dir=blocked_root / "run/results",
        remote_target_dir=Path("/remote/pi-agent-target"),
        max_age_hours=24.0,
        now=utc_now(),
        runner_mode="rch",
    )
    assert blocked_manifest["summary"]["status"] == "blocked", blocked_manifest
    assert any(
        entry["contract_id"] == "extension_criterion_policy"
        and entry["retrieval_status"] == "missing_after_run"
        for entry in blocked_manifest["entries"]
    ), blocked_manifest
    assert any(
        blocker["contract_id"] == "extension_criterion_policy"
        and blocker["blocker"] == EXTENSION_BLOCKER_BEAD
        for blocker in blocked_manifest["blockers"]
    ), blocked_manifest
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", help="Repository root. Defaults to this script's repo.")
    parser.add_argument(
        "--cargo-target-dir",
        help="Cargo target directory to inspect. Defaults to CARGO_TARGET_DIR or ./target.",
    )
    parser.add_argument("--local-results-dir", help="Perf run results directory.")
    parser.add_argument("--remote-target-dir", help="Remote CARGO_TARGET_DIR prefix for RCH source paths.")
    parser.add_argument("--runner-mode", default="unknown", help="Resolved cargo runner mode.")
    parser.add_argument("--output", help="Manifest output path. Defaults to stdout.")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(
            os.environ.get("PI_PERF_MAX_ARTIFACT_AGE_HOURS", DEFAULT_MAX_ARTIFACT_AGE_HOURS)
        ),
        help="Maximum accepted artifact age in hours.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run disposable self-tests.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()

    repo_root = Path(args.repo_root).resolve() if args.repo_root else repo_root_from_script()
    target_dir = resolve_target_dir(repo_root, args.cargo_target_dir or os.environ.get("CARGO_TARGET_DIR"))
    local_results_dir = Path(args.local_results_dir).resolve() if args.local_results_dir else None
    remote_target_dir = Path(args.remote_target_dir).expanduser() if args.remote_target_dir else None
    manifest = build_staging_manifest(
        repo_root=repo_root,
        target_dir=target_dir,
        local_results_dir=local_results_dir,
        remote_target_dir=remote_target_dir,
        max_age_hours=args.max_age_hours,
        now=utc_now(),
        runner_mode=args.runner_mode,
    )
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if manifest["summary"]["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
