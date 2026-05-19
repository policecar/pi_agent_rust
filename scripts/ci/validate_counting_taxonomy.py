#!/usr/bin/env python3
"""Validate counting taxonomy metadata in evidence artifacts.

This checker enforces the Phase-0 counting taxonomy contract:
- Every count must carry an explicit granularity label.
- LOC/provider/extension dimensions must include required side-by-side labels.
- Every metric must include tool provenance and command signature.

Usage:
  python3 scripts/ci/validate_counting_taxonomy.py --artifact ARTIFACT
  python3 scripts/ci/validate_counting_taxonomy.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def project_root_from_script() -> Path:
    # scripts/ci/validate_counting_taxonomy.py -> repo root is parents[2]
    return Path(__file__).resolve().parents[2]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_artifact(artifact: dict, contract: dict) -> list[str]:
    errors: list[str] = []

    required_dimensions = contract.get("required_dimensions", {})
    required_metric_fields = contract.get("required_metric_fields", [])
    required_provenance_fields = contract.get("required_tool_provenance_fields", [])
    expected_taxonomy_schema = contract.get("taxonomy_schema")

    taxonomy = artifact.get("counting_taxonomy")
    if not isinstance(taxonomy, dict):
        return ["missing top-level counting_taxonomy object"]

    schema = taxonomy.get("schema")
    if schema != expected_taxonomy_schema:
        errors.append(
            f"counting_taxonomy.schema must be {expected_taxonomy_schema!r}, got {schema!r}"
        )

    dimensions = taxonomy.get("dimensions")
    if not isinstance(dimensions, dict):
        return errors + ["counting_taxonomy.dimensions must be an object"]

    for dim_name, dim_contract in required_dimensions.items():
        dim = dimensions.get(dim_name)
        if not isinstance(dim, dict):
            errors.append(f"missing counting_taxonomy.dimensions.{dim_name}")
            continue

        metrics = dim.get("metrics")
        if not isinstance(metrics, list):
            errors.append(f"counting_taxonomy.dimensions.{dim_name}.metrics must be an array")
            continue

        required_labels = set(dim_contract.get("required_granularity_labels", []))
        seen_labels: set[str] = set()

        for idx, metric in enumerate(metrics):
            metric_path = f"counting_taxonomy.dimensions.{dim_name}.metrics[{idx}]"
            if not isinstance(metric, dict):
                errors.append(f"{metric_path} must be an object")
                continue

            for field in required_metric_fields:
                if field not in metric:
                    errors.append(f"{metric_path} missing field {field!r}")

            label = metric.get("granularity_label")
            if isinstance(label, str) and label.strip():
                seen_labels.add(label)
            else:
                errors.append(f"{metric_path}.granularity_label must be a non-empty string")

            value = metric.get("value")
            if not isinstance(value, (int, float)):
                errors.append(f"{metric_path}.value must be numeric")

            provenance = metric.get("tool_provenance")
            if not isinstance(provenance, dict):
                errors.append(f"{metric_path}.tool_provenance must be an object")
            else:
                for field in required_provenance_fields:
                    val = provenance.get(field)
                    if not isinstance(val, str) or not val.strip():
                        errors.append(f"{metric_path}.tool_provenance.{field} must be non-empty")

        missing_labels = sorted(required_labels - seen_labels)
        if missing_labels:
            errors.append(
                f"counting_taxonomy.dimensions.{dim_name} missing granularity labels: "
                + ", ".join(missing_labels)
            )

    return errors


def fixture_contract() -> dict:
    return {
        "taxonomy_schema": "pi.qa.counting_taxonomy.v1",
        "required_metric_fields": [
            "metric_key",
            "granularity_label",
            "value",
            "unit",
            "tool_provenance",
        ],
        "required_tool_provenance_fields": ["source", "command_signature"],
        "required_dimensions": {
            "providers": {
                "required_granularity_labels": [
                    "provider_canonical_ids",
                    "provider_alias_ids",
                ],
            },
        },
    }


def fixture_metric(label: str, value: int | float = 1) -> dict:
    return {
        "metric_key": "provider_breadth",
        "granularity_label": label,
        "value": value,
        "unit": "count",
        "tool_provenance": {
            "source": "fixture",
            "command_signature": "python3 fixture",
        },
    }


def fixture_artifact() -> dict:
    return {
        "counting_taxonomy": {
            "schema": "pi.qa.counting_taxonomy.v1",
            "dimensions": {
                "providers": {
                    "metrics": [
                        fixture_metric("provider_canonical_ids", 2),
                        fixture_metric("provider_alias_ids", 3),
                    ],
                },
            },
        },
    }


def run_self_test() -> int:
    contract = fixture_contract()
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    valid_errors = validate_artifact(fixture_artifact(), contract)
    require(valid_errors == [], f"valid fixture should pass, got {valid_errors!r}")

    missing_taxonomy_errors = validate_artifact({}, contract)
    require(
        missing_taxonomy_errors == ["missing top-level counting_taxonomy object"],
        f"missing taxonomy errors mismatch: {missing_taxonomy_errors!r}",
    )

    wrong_schema_artifact = fixture_artifact()
    wrong_schema_artifact["counting_taxonomy"]["schema"] = "wrong.schema"
    wrong_schema_errors = validate_artifact(wrong_schema_artifact, contract)
    require(
        any("counting_taxonomy.schema must be" in error for error in wrong_schema_errors),
        f"schema mismatch was not reported: {wrong_schema_errors!r}",
    )

    missing_label_artifact = fixture_artifact()
    missing_label_artifact["counting_taxonomy"]["dimensions"]["providers"]["metrics"] = [
        fixture_metric("provider_canonical_ids", 2),
    ]
    missing_label_errors = validate_artifact(missing_label_artifact, contract)
    require(
        any("provider_alias_ids" in error for error in missing_label_errors),
        f"missing label was not reported: {missing_label_errors!r}",
    )

    non_numeric_artifact = fixture_artifact()
    non_numeric_artifact["counting_taxonomy"]["dimensions"]["providers"]["metrics"][0][
        "value"
    ] = "two"
    non_numeric_errors = validate_artifact(non_numeric_artifact, contract)
    require(
        any(".value must be numeric" in error for error in non_numeric_errors),
        f"non-numeric value was not reported: {non_numeric_errors!r}",
    )

    blank_label_artifact = fixture_artifact()
    blank_label_artifact["counting_taxonomy"]["dimensions"]["providers"]["metrics"][0][
        "granularity_label"
    ] = ""
    blank_label_errors = validate_artifact(blank_label_artifact, contract)
    require(
        any(
            ".granularity_label must be a non-empty string" in error
            for error in blank_label_errors
        ),
        f"blank granularity label was not reported: {blank_label_errors!r}",
    )

    blank_provenance_artifact = fixture_artifact()
    blank_provenance_artifact["counting_taxonomy"]["dimensions"]["providers"]["metrics"][0][
        "tool_provenance"
    ]["command_signature"] = " "
    blank_provenance_errors = validate_artifact(blank_provenance_artifact, contract)
    require(
        any(
            "tool_provenance.command_signature must be non-empty" in error
            for error in blank_provenance_errors
        ),
        f"blank provenance was not reported: {blank_provenance_errors!r}",
    )

    if failures:
        print("Counting taxonomy validator self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("Counting taxonomy validator self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--artifact", required=False, help="Evidence artifact JSON to validate")
    parser.add_argument(
        "--contract",
        default=str(project_root_from_script() / "docs/counting-taxonomy-contract.json"),
        help="Counting taxonomy contract JSON",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic in-memory validator checks",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.artifact:
        print("ERROR: --artifact is required unless --self-test is used", file=sys.stderr)
        return 2

    artifact_path = Path(args.artifact)
    contract_path = Path(args.contract)

    if not artifact_path.exists():
        print(f"ERROR: artifact not found: {artifact_path}", file=sys.stderr)
        return 2
    if not contract_path.exists():
        print(f"ERROR: contract not found: {contract_path}", file=sys.stderr)
        return 2

    artifact = load_json(artifact_path)
    contract = load_json(contract_path)
    errors = validate_artifact(artifact, contract)

    if errors:
        print("Counting taxonomy validation: FAIL", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Counting taxonomy validation: PASS")
    print(f"  Artifact: {artifact_path}")
    print(f"  Contract: {contract_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
