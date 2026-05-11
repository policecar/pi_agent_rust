#!/usr/bin/env python3
"""Dry-run preflight for RCH artifact sync coverage.

The RCH worker mirror is governed by .rchignore-style rules. This guard checks
that artifact paths needed by remote cargo/test/report gates are not excluded by
those rules before an expensive remote run starts.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "pi.rch.artifact_sync_preflight.v1"

DEFAULT_REQUIRED_PATHS = (
    "tests/ext_conformance/artifacts",
    "tests/ext_conformance/artifacts/PROVENANCE_VERIFICATION.json",
    "tests/evidence_bundle/index.json",
    "tests/full_suite_gate/full_suite_verdict.json",
    "tests/perf/reports/bench_schema_registry.json",
)


@dataclass(frozen=True)
class IgnoreRule:
    line: int
    pattern: str
    anchored: bool
    negated: bool

    @property
    def source(self) -> str:
        return ".rchignore"


def normalize_posix_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.strip("/")


def load_ignore_rules(ignore_file: Path) -> tuple[list[IgnoreRule], list[str]]:
    errors: list[str] = []
    if not ignore_file.exists():
        return [], [f"ignore file is missing: {ignore_file}"]

    rules: list[IgnoreRule] = []
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], [f"failed to read ignore file {ignore_file}: {exc}"]

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        negated = stripped.startswith("!")
        if negated:
            stripped = stripped[1:].strip()
        if not stripped:
            continue
        stripped = stripped.replace("\\", "/")
        rules.append(
            IgnoreRule(
                line=line_number,
                pattern=stripped,
                anchored=stripped.startswith("/"),
                negated=negated,
            )
        )
    return rules, errors


def core_rule_matches(pattern: str, rel_path: str) -> bool:
    body = pattern.lstrip("/")
    if not body:
        return False

    if body.endswith("/**"):
        base = body[:-3].rstrip("/")
        return rel_path == base or rel_path.startswith(f"{base}/")

    if body.endswith("/"):
        base = body.rstrip("/")
        return rel_path == base or rel_path.startswith(f"{base}/")

    if fnmatch.fnmatchcase(rel_path, body):
        return True

    if "/" not in body:
        return any(fnmatch.fnmatchcase(component, body) for component in rel_path.split("/"))

    return False


def rule_matches(rule: IgnoreRule, rel_path: str) -> bool:
    rel_path = normalize_posix_path(rel_path)
    if rule.anchored:
        return core_rule_matches(rule.pattern, rel_path)

    if core_rule_matches(rule.pattern, rel_path):
        return True

    components = rel_path.split("/")
    for index in range(1, len(components)):
        if core_rule_matches(rule.pattern, "/".join(components[index:])):
            return True
    return False


def resolve_required_path(repo_root: Path, raw_path: str) -> tuple[str, Path]:
    path = Path(raw_path)
    if path.is_absolute():
        full_path = path
        try:
            rel_path = full_path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            rel_path = normalize_posix_path(raw_path)
    else:
        rel_path = normalize_posix_path(raw_path)
        full_path = repo_root / rel_path
    return rel_path, full_path


def matched_rule_payload(rule: IgnoreRule, matched: bool) -> dict[str, Any]:
    state = "include" if rule.negated else "exclude"
    return {
        "source": rule.source,
        "line": rule.line,
        "pattern": rule.pattern,
        "anchored": rule.anchored,
        "state": state,
        "matched": matched,
    }


def evaluate_required_paths(
    repo_root: Path, rules: list[IgnoreRule], required_paths: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    required_results: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []

    for raw_path in required_paths:
        rel_path, full_path = resolve_required_path(repo_root, raw_path)
        matched_rules: list[dict[str, Any]] = []
        final_ignored = False
        final_rule: IgnoreRule | None = None

        for rule in rules:
            matched = rule_matches(rule, rel_path)
            if not matched:
                continue
            matched_rules.append(matched_rule_payload(rule, matched=True))
            final_ignored = not rule.negated
            final_rule = rule

        exists = full_path.exists()
        path_result = {
            "path": rel_path,
            "exists": exists,
            "kind": "directory" if full_path.is_dir() else "file" if full_path.is_file() else "missing",
            "matched_rules": matched_rules,
            "included": exists and not final_ignored,
        }
        required_results.append(path_result)

        if not exists:
            violations.append(
                {
                    "path": rel_path,
                    "source": "required_paths",
                    "line": None,
                    "pattern": None,
                    "reason": "missing_required_path",
                    "message": f"required path is missing from the repo: {rel_path}",
                }
            )
            continue

        if final_ignored and final_rule is not None:
            violations.append(
                {
                    "path": rel_path,
                    "source": final_rule.source,
                    "line": final_rule.line,
                    "pattern": final_rule.pattern,
                    "reason": "required_path_excluded",
                    "message": (
                        f"{rel_path} is excluded by {final_rule.source}:{final_rule.line} "
                        f"pattern {final_rule.pattern!r}"
                    ),
                }
            )

    return required_results, violations


def build_report(repo_root: Path, ignore_file: Path, required_paths: list[str]) -> dict[str, Any]:
    rules, load_errors = load_ignore_rules(ignore_file)
    required_results, violations = evaluate_required_paths(repo_root, rules, required_paths)

    for error in load_errors:
        violations.append(
            {
                "path": str(ignore_file),
                "source": ".rchignore",
                "line": None,
                "pattern": None,
                "reason": "ignore_file_error",
                "message": error,
            }
        )

    return {
        "schema": SCHEMA,
        "mode": "dry-run",
        "status": "fail" if violations else "pass",
        "repo_root": str(repo_root),
        "ignore_file": str(ignore_file),
        "required_paths": required_results,
        "violations": violations,
        "summary": {
            "required_path_count": len(required_results),
            "violation_count": len(violations),
        },
    }


def print_text_report(report: dict[str, Any]) -> None:
    print(f"RCH artifact sync preflight: {report['status'].upper()}")
    for item in report["required_paths"]:
        state = "included" if item["included"] else "blocked"
        print(f"- {item['path']}: {state} ({item['kind']})")
        for rule in item["matched_rules"]:
            print(
                f"  matched {rule['source']}:{rule['line']} "
                f"{rule['pattern']!r} -> {rule['state']}"
            )

    if report["violations"]:
        print("\nViolations:")
        for violation in report["violations"]:
            print(f"- {violation['message']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root to evaluate. Defaults to the current directory.",
    )
    parser.add_argument(
        "--ignore-file",
        default=None,
        help="Path to .rchignore. Defaults to <repo-root>/.rchignore.",
    )
    parser.add_argument(
        "--required-path",
        action="append",
        dest="required_paths",
        help="Repo-relative artifact path that must be present in the RCH mirror.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    ignore_file = Path(args.ignore_file).resolve() if args.ignore_file else repo_root / ".rchignore"
    required_paths = args.required_paths or list(DEFAULT_REQUIRED_PATHS)

    report = build_report(repo_root, ignore_file, required_paths)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
