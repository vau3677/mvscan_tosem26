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
        "For each card, evaluate C1 through C5 in your assigned CSV. Leave passing criteria blank, record only `N` or `U` exceptions with a short note, and set `review_complete` to `Y` after checking all five criteria.",
        "",
    ]
    manifest = []
    for review_id, packet_path, packet in packets:
        evidence = packet.get("published_evidence", {})
        excerpts = packet.get("source_excerpts", [])
        card_name = f"{review_id}.md"
        available = [item for item in excerpts if item.get("status") == "AVAILABLE"]
        lines = [
            f"# {review_id}: {clean(packet.get('report_identity'))}",
            "",
            "## Published report facts",
            "",
            f"- **Root cause:** {clean(evidence.get('root_cause_evidence'))}",
            f"- **Documented consequence:** {clean(evidence.get('exploitation_evidence'))}",
            f"- **Documented fix:** {clean(evidence.get('fix_strategy_evidence'))}",
            f"- **Report:** {clean(packet.get('report_url'))}",
            "",
            "## Supporting source evidence",
            "",
        ]
        if available:
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
                "No source excerpt is available in the frozen packet. Use the published report facts when they clearly establish a criterion; otherwise mark that criterion `U` and state what evidence is missing.",
                "",
            ]
        lines += [
            "## Traceability",
            "",
            f"- Oracle row: `{packet['oracle_row_id']}`",
            f"- Frozen source packet: `../isu_packets/{packet_path.name}`",
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
