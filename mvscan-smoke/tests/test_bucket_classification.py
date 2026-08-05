from __future__ import annotations
import json, os, subprocess, sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "classification"
BASELINE = ROOT / "results" / "baseline"
RESULTS.mkdir(parents=True, exist_ok=True)

BASE_ENV = {
    "MVSCAN_ABLATION": "full",
    "SINK_TEST": "none",
    "DIVERGENCE_BUDGET": "1000",
    "INIT_ONLY_FILTER": "0",
    "ADMIN_WRITES_BENIGN": "0",
    "REQUIRE_SAME_SLOT_KEY": "1",
    "COARSE_DEDUP": "1",
}

CASES = [
    {
        "name": "order-test",
        "contract": "contracts/OrderTest.sol",
        "required": {"multi_var_intra_contract"},
        "forbidden": {"multi_var_cross_contract"},
    },
    {
        "name": "order-test-reversed",
        "contract": "contracts/OrderTestReversed.sol",
        "required": {"multi_var_intra_contract"},
        "forbidden": {"multi_var_cross_contract"},
    },
    {
        "name": "same-contract-branch",
        "contract": "contracts/SameContractBranch.sol",
        "required": {"multi_var_intra_contract"},
        "forbidden": {"multi_var_cross_contract"},
    },
    {
        "name": "same-contract-mappings",
        "contract": "contracts/SameContractMappings.sol",
        "required": {"multi_var_intra_contract"},
        "forbidden": {"multi_var_cross_contract"},
    },
    {
        "name": "inheritance-same-base",
        "contract": "contracts/InheritanceSameBase.sol",
        "required": {"multi_var_intra_contract"},
        "forbidden": {"multi_var_cross_contract"},
    },
    {
        "name": "inheritance-mixed",
        "contract": "contracts/InheritanceMixed.sol",
        "required": {"multi_var_cross_contract"},
        "forbidden": set(),
    },
    {
        "name": "cross-contract-branch",
        "contract": "contracts/CrossContractBranch.sol",
        "required": {"multi_var_cross_contract"},
        "forbidden": set(),
    },
    {
        "name": "single-variable",
        "contract": "contracts/SingleVariable.sol",
        "required": {"single_var_cross_tx"},
        "forbidden": {
            "multi_var_intra_contract",
            "multi_var_cross_contract",
        },
    },
]


def run_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    output_path = RESULTS / f"{case['name']}.json"
    output_path.unlink(missing_ok=True)

    env = os.environ.copy()
    env.update(BASE_ENV)
    env.update(case.get("extra_env", {}))
    env["ISD_JSON_OUT"] = str(output_path)

    command = [
        "slither",
        case["contract"],
        "--detect",
        "inconsistent_state",
        "--solc-disable-warnings",
        "--fail-none",
    ]

    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    if completed.returncode != 0:
        print(f"\nFAIL {case['name']}: Slither exited with "
              f"{completed.returncode}")
        print(completed.stdout)
        raise SystemExit(1)

    if not output_path.exists():
        print(f"\nFAIL {case['name']}: output file was not created")
        print(completed.stdout)
        raise SystemExit(1)

    findings = json.loads(output_path.read_text())

    if not isinstance(findings, list):
        raise AssertionError(
            f"{case['name']}: output must be a JSON list"
        )

    patterns = Counter(
        finding.get("pattern")
        for finding in findings
    )

    missing = case["required"] - set(patterns)
    forbidden = case["forbidden"] & set(patterns)

    print(
        f"{case['name']}: "
        f"{len(findings)} finding(s), patterns={dict(patterns)}"
    )

    if missing:
        print(f"\nFAIL {case['name']}: missing {sorted(missing)}")
        print(json.dumps(findings, indent=2, sort_keys=True))
        raise SystemExit(1)

    if forbidden:
        print(
            f"\nFAIL {case['name']}: forbidden classifications "
            f"{sorted(forbidden)}"
        )
        print(json.dumps(findings, indent=2, sort_keys=True))
        raise SystemExit(1)

    return findings


def scrub_unstable_fields(value: Any) -> Any:
    """
    Remove only:
      - the classification field being intentionally repaired;
      - process-local branch-group IDs based on Python id().
    Sort all lists so set iteration order cannot cause a false mismatch.
    """
    if isinstance(value, dict):
        cleaned = {
            key: scrub_unstable_fields(item)
            for key, item in value.items()
            if key not in {"pattern", "branch_groups"}
        }
        return cleaned

    if isinstance(value, list):
        cleaned_items = [
            scrub_unstable_fields(item)
            for item in value
        ]

        return sorted(
            cleaned_items,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                default=str,
            ),
        )

    return value


def assert_payload_unchanged(
    before_path: Path,
    after_path: Path,
) -> None:
    if not before_path.exists():
        raise AssertionError(
            f"Missing baseline file: {before_path}"
        )

    before = json.loads(before_path.read_text())
    after = json.loads(after_path.read_text())

    before_clean = scrub_unstable_fields(before)
    after_clean = scrub_unstable_fields(after)

    if before_clean != after_clean:
        print("\nFAIL: discovery payload changed")
        print("\nBEFORE, excluding pattern/branch-group IDs:")
        print(json.dumps(before_clean, indent=2, sort_keys=True))
        print("\nAFTER, excluding pattern/branch-group IDs:")
        print(json.dumps(after_clean, indent=2, sort_keys=True))
        raise SystemExit(1)


def semantic_order_test(
    first: list[dict[str, Any]],
    second: list[dict[str, Any]],
) -> None:
    """
    Compare declaration-order variants while removing source-file and
    source-line differences caused by using two separate Solidity files.
    """

    def normalize(findings: list[dict[str, Any]]) -> Any:
        normalized = []

        for finding in findings:
            vars_normalized = []

            for var in finding.get("vars", []):
                item = {
                    key: value
                    for key, value in var.items()
                    if key not in {
                        "branch_groups",
                        "slot",
                        "base_slot",
                    }
                }
                vars_normalized.append(item)

            normalized.append({
                "pattern": finding.get("pattern"),
                "vars": sorted(
                    vars_normalized,
                    key=lambda item: json.dumps(
                        item,
                        sort_keys=True,
                    ),
                ),
                "tx_functions": sorted(
                    tx.rsplit("::", 1)[-1]
                    for tx in finding.get("tx_set", [])
                ),
                "writer_sigs": sorted(
                    writer.get("sig")
                    for writer in finding.get("writers", [])
                ),
                "reader_sigs": sorted(
                    reader.get("sig")
                    for reader in finding.get("readers", [])
                ),
                "op_patterns": sorted(
                    finding.get("op_patterns", [])
                ),
                "shape": finding.get("shape", {}),
            })

        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
            ),
        )

    if normalize(first) != normalize(second):
        print("\nFAIL: declaration order changed semantic findings")
        print("\nCALLER FIRST:")
        print(json.dumps(normalize(first), indent=2, sort_keys=True))
        print("\nCALLEE FIRST:")
        print(json.dumps(normalize(second), indent=2, sort_keys=True))
        raise SystemExit(1)


def main() -> None:
    outputs = {}

    for case in CASES:
        outputs[case["name"]] = run_case(case)

    assert_payload_unchanged(
        BASELINE / "order-test-before.json",
        RESULTS / "order-test.json",
    )
    print(
        "order-test: pre/post payload unchanged "
        "except classification and branch-group IDs"
    )

    assert_payload_unchanged(
        BASELINE / "order-test-reversed-before.json",
        RESULTS / "order-test-reversed.json",
    )
    print(
        "order-test-reversed: pre/post payload unchanged "
        "except classification and branch-group IDs"
    )

    semantic_order_test(
        outputs["order-test"],
        outputs["order-test-reversed"],
    )
    print("declaration-order semantic comparison: MATCH")

    print("\nALL CLASSIFICATION TESTS PASSED")


if __name__ == "__main__":
    main()
