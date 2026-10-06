#!/usr/bin/env python3
"""Render detector-blind, traceable one-minute cards from frozen ISU packets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def clean(value: object) -> str:
    return str(value or "Not provided in the frozen packet.").strip()


def build_cards(packets_dir: Path, output: Path) -> int:
    if output.exists():
        raise RuntimeError(f"output exists: {output}")
    output.mkdir(parents=True)
    packets = []
    for path in packets_dir.glob("*.json"):
        packet = json.loads(path.read_text(encoding="utf-8"))
        packets.append((str(packet["review_id"]), path, packet))
    packets.sort()
    index = [
        "# Known historical findings",
        "",
        "Read these cards in order. Each card contains only published finding evidence and pinned source evidence from its frozen ISU packet. It contains no MV-Scan output.",
        "",
        "For each card, answer one question in your assigned CSV: **Does the documented defect essentially require two or more persistent state entities to become inconsistent across operations?** Enter `Y`, `N`, or `U` (insufficient evidence).",
        "",
    ]
    manifest = []
    for review_id, packet_path, packet in packets:
        evidence = packet.get("published_evidence", {})
        resolution = packet.get("source_resolution", {})
        excerpts = packet.get("source_excerpts", [])
        card_name = f"{review_id}.md"
        available = [item for item in excerpts if item.get("status") == "AVAILABLE"]
        lines = [
            f"# {review_id}: {clean(packet.get('report_identity'))}",
            "",
            "## One-minute decision",
            "",
            "Does the documented defect essentially require **two or more persistent state entities to become inconsistent across operations**?",
            "",
            "- `Y`: yes, the multi-entity relationship is essential to the documented defect.",
            "- `N`: no, the defect is unary or multiple entities are merely incidental.",
            "- `U`: the evidence below is insufficient to decide.",
            "",
            "## Published report facts",
            "",
            f"- **Root cause:** {clean(evidence.get('root_cause_evidence'))}",
            f"- **Documented consequence:** {clean(evidence.get('exploitation_evidence'))}",
            f"- **Documented fix:** {clean(evidence.get('fix_strategy_evidence'))}",
            f"- **Report:** {clean(packet.get('report_url'))}",
            "",
            "## Pinned source provenance",
            "",
            f"- **Repository:** {clean(resolution.get('repository'))}",
            f"- **Vulnerable revision:** {clean(resolution.get('vulnerable_revision'))}",
            f"- **Affected source paths:** {', '.join(map(str, resolution.get('affected_source_paths', []))) or 'Not provided in the frozen packet.'}",
            f"- **Build/source status:** {clean(resolution.get('build_coverage'))}; {clean(resolution.get('status'))}",
            "",
            "## Supporting source evidence",
            "",
        ]
        if available:
            lines += [
                "The exact frozen excerpts are included below for spot-checking. The published report facts above are the primary one-minute view.",
                "",
            ]
            for number, item in enumerate(available, 1):
                label = f"{clean(item.get('resolved_path') or item.get('file'))}:{item.get('start_line', '?')}-{item.get('end_line', '?')}"
                lines += [
                    f"<details><summary>Source excerpt {number}: {label}</summary>",
                    "",
                    "```solidity",
                    clean(item.get("source")),
                    "```",
                    "",
                    "</details>",
                    "",
                ]
        else:
            lines += [
                "No source excerpt is available in the frozen packet. Use `U` unless the published report facts alone clearly establish the classification.",
                "",
            ]
        lines += [
            "## Traceability",
            "",
            f"- Oracle row: `{packet['oracle_row_id']}`",
            f"- Frozen source packet: `../isu_packets/{packet_path.name}`",
            "- Detector output consulted in this card: **No**",
            "",
        ]
        (output / card_name).write_text("\n".join(lines), encoding="utf-8")
        index.append(f"- [{review_id}: {clean(packet.get('report_identity'))}]({card_name})")
        manifest.append({
            "review_id": review_id,
            "oracle_row_id": packet["oracle_row_id"],
            "card": card_name,
            "source_packet": f"../isu_packets/{packet_path.name}",
            "available_source_excerpts": len(available),
        })
    (output / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    (output / "TRACEABILITY.json").write_text(
        json.dumps({"schema_version": 1, "cards": manifest}, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return len(manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packets", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = build_cards(args.packets, args.output)
    print(json.dumps({"cards": count, "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
