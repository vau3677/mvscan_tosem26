"""Structural-only compilation metadata discovery for subject manifests."""
from __future__ import annotations
import json, os
from pathlib import Path
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from .inconsistent_state import _compilation_unit_id, compilation_metadata

_UNITS: dict[str, dict[str, dict]] = {}

class MVScanMetadata(AbstractDetector):
    ARGUMENT = "mvscan_metadata"
    HELP = "Emit compilation-unit identity and metadata without semantic analysis"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.INFORMATIONAL
    WIKI = "https://example.invalid/mvscan-metadata"
    WIKI_TITLE = "MV-Scan structural metadata"
    WIKI_DESCRIPTION = "Records compilation identity only."
    WIKI_EXPLOIT_SCENARIO = "Not applicable."
    WIKI_RECOMMENDATION = "Not applicable."

    def _detect(self):
        output = os.environ.get("ISD_JSON_OUT")
        if not output:
            return []
        path = Path(output).resolve()
        units = _UNITS.setdefault(str(path), {})
        unit_id = _compilation_unit_id(self.compilation_unit)
        units[unit_id] = {"unit_id": unit_id, "compilation_metadata": compilation_metadata(self)}
        document = {"schema_version": 1, "mode": "STRUCTURAL_METADATA_ONLY", "compilation_units": [units[key] for key in sorted(units)]}
        temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
        temporary.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.replace(temporary, path)
        return []
