"""Canonical detector configurations used by the evaluation runner."""

VARIANTS = {
    "B0": {
        "display_name": "Reference",
        "MVSCAN_ABLATION": "full",
        "SINK_TEST": "value",
    },
    "A1": {
        "display_name": "SV-only",
        "MVSCAN_ABLATION": "sv_only",
        "SINK_TEST": "value",
    },
    "A2": {
        "display_name": "No branch co-use grouping",
        "MVSCAN_ABLATION": "no_branch_groups",
        "SINK_TEST": "value",
    },
    "A3_IB0": {
        "display_name": "A3/IB0 Predicate-only baseline",
        "MVSCAN_ABLATION": "no_multi_return_groups",
        "SINK_TEST": "value",
    },
    "A4": {
        "display_name": "No external-state abstraction",
        "MVSCAN_ABLATION": "no_external_state",
        "SINK_TEST": "value",
    },
    "A5": {
        "display_name": "Mapping-insensitive",
        "MVSCAN_ABLATION": "mapping_insensitive",
        "SINK_TEST": "value",
    },
    "A6": {
        "display_name": "No late sink filter",
        "MVSCAN_ABLATION": "full",
        "SINK_TEST": "none",
    },
}
