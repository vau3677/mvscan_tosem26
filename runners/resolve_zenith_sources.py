#!/usr/bin/env python3
"""Apply exact repository revisions explicitly embedded in Zenith report PDFs."""

from __future__ import annotations

import csv
from pathlib import Path

from runners.common import ROOT

RESOLUTION = ROOT / "benchmarks" / "isu" / "source_resolution.csv"
EVIDENCE_ROOT = ROOT / "benchmarks" / "isu" / "source_resolution_evidence" / "zenith-portfolio" / "reports"
EXPLICIT = {
    "2024-09-legion-evm-zenith#h-3": (
        "https://github.com/Legion-Team/evm-contracts.git",
        "c020bd1b84faab99d1b8738b48d1e253e4557671",
        "2024-09-legion-evm-zenith.pdf",
        "https://github.com/Legion-Team/evm-contracts/blob/c020bd1b84faab99d1b8738b48d1e253e4557671/src/LegionBaseSale.sol#L210",
    ),
    "2024-06-playfi-proleague#h-1": (
        "https://github.com/PlayFi-Labs/node-license-sale-contracts.git",
        "219c9ac0c963074cdd032f1188d0b5b7f6e3ccbb",
        "2024-06-playfi-zenith.pdf",
        "https://github.com/PlayFi-Labs/node-license-sale-contracts/blob/219c9ac0c963074cdd032f1188d0b5b7f6e3ccbb/contracts/PlayFiLicenseSale.sol#L210",
    ),
    "2024-06-playfi-proleague#h-2": (
        "https://github.com/PlayFi-Labs/node-license-sale-contracts.git",
        "219c9ac0c963074cdd032f1188d0b5b7f6e3ccbb",
        "2024-06-playfi-zenith.pdf",
        "https://github.com/PlayFi-Labs/node-license-sale-contracts/blob/219c9ac0c963074cdd032f1188d0b5b7f6e3ccbb/contracts/PlayFiLicenseSale.sol#L181",
    ),
    "2024-jul-gemnify-proleague#h-2": (
        "https://github.com/GMX-For-NFT/gemnify-contract.git",
        "4810eb86d3391ba9e2eab26a725e9c7f63a3fa9e",
        "2024-07-gemnify-zenith.pdf",
        "https://github.com/GMX-For-NFT/gemnify-contract/blob/4810eb86d3391ba9e2eab26a725e9c7f63a3fa9e/contracts/core/libraries/logic/PositionLogic.sol#L642-L661",
    ),
    "2024-jul-gemnify-proleague#h-5": (
        "https://github.com/GMX-For-NFT/gemnify-contract.git",
        "4810eb86d3391ba9e2eab26a725e9c7f63a3fa9e",
        "2024-07-gemnify-zenith.pdf",
        "https://github.com/GMX-For-NFT/gemnify-contract/blob/4810eb86d3391ba9e2eab26a725e9c7f63a3fa9e/contracts/core/Vault.sol#L540",
    ),
    "2024-06-strateg-proleague#h-1": (
        "https://github.com/strateg-protocol/strateg-protocol-core.git",
        "325a2cca5bca189e194f48cfe561b0ed16fad527",
        "2024-06-strateg-zenith.pdf",
        "https://github.com/strateg-protocol/strateg-protocol-core/blob/325a2cca5bca189e194f48cfe561b0ed16fad527/contracts/StrategERC3525.sol#L258-L260",
    ),
    "2024-06-strateg-proleague#h-4": (
        "https://github.com/strateg-protocol/strateg-protocol-core.git",
        "3705996c0791bf6ad58003fb19070ccafcf78c6b",
        "2024-06-strateg-zenith.pdf",
        "https://github.com/strateg-protocol/strateg-protocol-core/blob/3705996c0791bf6ad58003fb19070ccafcf78c6b/contracts/StrategVault.sol#L362-L411",
    ),
}


def main() -> int:
    rows = list(csv.DictReader(RESOLUTION.open(newline="", encoding="utf-8")))
    fields = rows[0].keys()
    updated = 0
    for row in rows:
        evidence = EXPLICIT.get(row["report_identity"])
        if not evidence:
            continue
        repository, revision, pdf_name, source_link = evidence
        pdf_path = EVIDENCE_ROOT / pdf_name
        if not pdf_path.is_file():
            raise FileNotFoundError(pdf_path)
        row.update({
            "resolution_status": "RESOLVED_EXPLICIT_ZENITH_PDF",
            "source_repository": repository,
            "vulnerable_revision": revision,
            "source_reference": source_link,
            "affected_source_paths": "",
            "explicit_blob_links": f'["{source_link}"]',
            "section_sha256": "",
            "resolution_note": f"exact repository and revision from hyperlink annotation in {pdf_name}",
        })
        updated += 1
    with RESOLUTION.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    print(f"updated={updated}")
    return 0 if updated == 7 else 1


if __name__ == "__main__":
    raise SystemExit(main())
