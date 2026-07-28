import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from variants import VARIANTS


DETECTOR_ROOT = Path(__file__).resolve().parents[1] / "slither-si-detector"
PROBE = """
import inspect
import json
from slither.detectors.inconsistent_state import inconsistent_state
from slither.detectors.inconsistent_state.utils import icfg

detect_source = inspect.getsource(inconsistent_state.InconsistentState._detect)
print(json.dumps({
    "ENABLE_MULTIVAR_GROUPS": icfg.ENABLE_MULTIVAR_GROUPS,
    "ENABLE_BRANCH_GROUPS": icfg.ENABLE_BRANCH_GROUPS,
    "ENABLE_MULTI_RETURN_GROUPS": icfg.ENABLE_MULTI_RETURN_GROUPS,
    "ENABLE_EXTERNAL_STATE": icfg.ENABLE_EXTERNAL_STATE,
    "PSEUDO_SITE_UNION": (
        "for v in (site_vars or members)" in detect_source
        and "if ENABLE_PSEUDO_SITE_UNION" not in detect_source
    ),
    "MAPPING_MODE": icfg.MAPPING_MODE,
    "REQUIRE_SAME_SLOT_KEY": icfg.REQUIRE_SAME_SLOT_KEY,
}))
"""

EXPECTED_B0 = {
    "ENABLE_MULTIVAR_GROUPS": True,
    "ENABLE_BRANCH_GROUPS": True,
    "ENABLE_MULTI_RETURN_GROUPS": True,
    "ENABLE_EXTERNAL_STATE": True,
    "PSEUDO_SITE_UNION": True,
    "MAPPING_MODE": "precise",
    "REQUIRE_SAME_SLOT_KEY": True,
}

EXPECTED_A3_IB0 = {
    **EXPECTED_B0,
    "ENABLE_MULTI_RETURN_GROUPS": False,
}


def run_config_probe(**environment):
    env = os.environ.copy()
    env.update(environment)
    return subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=DETECTOR_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def probe_config(variant_id):
    variant = VARIANTS[variant_id]
    result = run_config_probe(
        MVSCAN_ABLATION=variant["MVSCAN_ABLATION"],
        SINK_TEST=variant["SINK_TEST"],
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_evaluation_manifest_has_exactly_seven_runs():
    assert tuple(VARIANTS) == (
        "B0", "A1", "A2", "A3_IB0", "A4", "A5", "A6"
    )


def test_a3_ib0_differs_from_reference_only_by_multi_return_grouping():
    b0 = probe_config("B0")
    a3_ib0 = probe_config("A3_IB0")

    assert b0 == EXPECTED_B0
    assert a3_ib0 == EXPECTED_A3_IB0

    changed = {
        key
        for key in EXPECTED_B0
        if EXPECTED_B0[key] != EXPECTED_A3_IB0[key]
    }
    assert changed == {"ENABLE_MULTI_RETURN_GROUPS"}


REMOVED_MODES = (
    "ib" + "0",
    "naive" + "_co_use",
    "naive" + "_couse",
)


@pytest.mark.parametrize("removed_mode", REMOVED_MODES)
def test_removed_legacy_baseline_modes_fail(removed_mode):
    result = run_config_probe(MVSCAN_ABLATION=removed_mode)

    assert result.returncode != 0
    assert "unknown MVSCAN_ABLATION" in result.stderr
