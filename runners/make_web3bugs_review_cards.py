#!/usr/bin/env python3
import csv
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path


def entity(value):
    if isinstance(value, dict):
        key = value.get("entity_key", [])
        name = value.get("name") or (key[-1] if key else "unknown")
        location = key[1] if len(key) > 1 else ""
        slot = value.get("key")
        return f"`{name}` ({location}{f', key {slot}' if slot else ''})"
    if isinstance(value, list):
        name = value[-1] if value else "unknown"
        location = value[1] if len(value) > 1 else ""
        return f"`{name}` ({location})"
    return f"`{value}`"


def relation_members(packet):
    relation = packet.get("relation", [])
    return relation.get("members", []) if isinstance(relation, dict) else relation


def short_function(value):
    return str(value or "unknown").split("::")[-1]


def bullets(values):
    return "\n".join(f"- {entity(v)}" for v in values) or "- None serialized"


def witness_groups(packet):
    groups = defaultdict(lambda: {"contexts": set(), "pairs": set(), "sinks": set(), "ordering": set()})
    for witness in packet.get("reader_witnesses", []):
        reader = witness.get("reader", {})
        key = (reader.get("signature") or reader.get("block", {}).get("function_key"), reader.get("file"), reader.get("line"))
        group = groups[key]
        owner = reader.get("context", {}).get("owner")
        if owner:
            group["contexts"].add(short_function(owner))
        for evidence in witness.get("relation_evidence", []):
            writer = evidence.get("writer_member") or evidence.get("writer_location") or {}
            read = evidence.get("reader_member") or evidence.get("reader_location") or {}
            group["pairs"].add((entity(writer), entity(read)))
        for sink in witness.get("sinks", []):
            group["sinks"].add(f"{sink.get('kind', 'unknown')} in {short_function(sink.get('function_key'))}")
        group["ordering"].add(f"writer→reader={witness.get('writer_reaches_reader')}; reader→writer={witness.get('reader_reaches_writer')}")
    return groups


def make_card(packet):
    review_id = packet["review_id"]
    writer = packet.get("writer_block", {})
    lines = [
        f"# {review_id} · Subject {packet.get('subject', '')}",
        "",
        "## Candidate relation",
        "",
        bullets(relation_members(packet)),
        "",
        "**Written by the partial transition**",
        "",
        bullets(packet.get("written_members", [])),
        "",
        "**Potentially left stale**",
        "",
        bullets(packet.get("potentially_stale_members", [])),
        "",
        "## Writer transition",
        "",
        f"- Entry context: `{short_function(packet.get('writer_owner'))}`",
        f"- Write site: `{short_function(writer.get('function_key'))}`",
    ]
    constraints = packet.get("structural_claim", {}).get("key_equality_constraints", [])
    if constraints:
        lines += ["- Key constraints: `" + json.dumps(constraints, ensure_ascii=False) + "`"]

    lines += ["", "## Omitted-state consumption", ""]
    groups = witness_groups(packet)
    if not groups:
        lines.append("No reader witness was serialized.")
    for (signature, file, line), group in groups.items():
        lines += [f"### `{short_function(signature)}` · {file or 'unknown file'}:{line or '?'}", ""]
        for writer_member, reader_member in sorted(group["pairs"]):
            lines.append(f"- Relation flow: {writer_member} → {reader_member}")
        lines.append("- Modeled sinks: " + "; ".join(sorted(group["sinks"])))
        lines.append("- Execution contexts: " + ", ".join(sorted(group["contexts"])))
        lines.append("- Serialized ordering: " + "; ".join(sorted(group["ordering"])))
        lines.append("")

    origins = packet.get("structural_claim", {}).get("origin_sites", [])
    if origins:
        lines += ["## Relation-origin expressions", ""]
        for origin in origins:
            lines.append(f"- `{origin.get('expression', '')}` in `{short_function(origin.get('function_key'))}`")
        lines.append("")

    excerpts = [x for x in packet.get("source_excerpts", []) if x.get("status", "AVAILABLE") == "AVAILABLE" and x.get("source")]
    if excerpts:
        lines += ["## Relevant source", ""]
        seen = set()
        for excerpt in excerpts:
            signature = (excerpt.get("file"), excerpt.get("start_line"), excerpt.get("end_line"), excerpt.get("source"))
            if signature in seen:
                continue
            seen.add(signature)
            lines += [f"### `{excerpt.get('file')}` · lines {excerpt.get('start_line', '?')}–{excerpt.get('end_line', '?')}", "", "```solidity", excerpt["source"].rstrip(), "```", ""]

    lines += [
        "## Decision",
        "",
        "| Field | Entry |",
        "|---|---|",
        "| C1 |  |",
        "| C2 |  |",
        "| C3 |  |",
        "| C4 |  |",
        "| C5 |  |",
        "| Label |  |",
        "| NONBUG cause |  |",
        "| Evidence note |  |",
        "",
    ]
    return "\n".join(lines)


def compact_name(value):
    if isinstance(value, dict):
        return value.get("name") or compact_name(value.get("entity_key", []))
    if isinstance(value, list):
        return str(value[-1]).split(".")[-1] if value else "unknown"
    return str(value).split(".")[-1]


def grouped_consumption(packet):
    grouped = defaultdict(lambda: {"readers": set(), "sinks": set(), "contexts": set(), "orders": set()})
    for witness in packet.get("reader_witnesses", []):
        reader = witness.get("reader", {})
        reader_site = f"{short_function(reader.get('signature') or reader.get('block', {}).get('function_key'))} at {reader.get('file', 'unknown')}:{reader.get('line', '?')}"
        members = set()
        for evidence in witness.get("relation_evidence", []):
            member = evidence.get("reader_member") or evidence.get("reader_location") or {}
            members.add(compact_name(member))
        for member in members or {"unspecified omitted state"}:
            item = grouped[member]
            item["readers"].add(reader_site)
            item["sinks"].update(f"{s.get('kind', 'unknown')} in {short_function(s.get('function_key'))}" for s in witness.get("sinks", []))
            owner = reader.get("context", {}).get("owner")
            if owner:
                item["contexts"].add(short_function(owner))
            item["orders"].add((witness.get("writer_reaches_reader"), witness.get("reader_reaches_writer")))
    return grouped


def choose_excerpts(packet, limit=3):
    available = [x for x in packet.get("source_excerpts", []) if x.get("status", "AVAILABLE") == "AVAILABLE" and x.get("source")]
    writer_line = packet.get("writer_block", {}).get("line")
    reader_lines = {w.get("reader", {}).get("line") for w in packet.get("reader_witnesses", [])}
    def score(x):
        start, end = x.get("start_line", 0), x.get("end_line", 0)
        return (3 if writer_line and start <= writer_line <= end else 0) + (2 if any(v and start <= v <= end for v in reader_lines) else 0)
    chosen = []
    for excerpt in sorted(available, key=score, reverse=True):
        overlaps = any(
            excerpt.get("file") == prior.get("file")
            and excerpt.get("start_line", 0) <= prior.get("end_line", 0)
            and prior.get("start_line", 0) <= excerpt.get("end_line", 0)
            for prior in chosen
        )
        if not overlaps:
            chosen.append(excerpt)
        if len(chosen) == limit:
            break
    return chosen


def readable_card(packet):
    relation = ", ".join(f"`{compact_name(x)}`" for x in relation_members(packet)) or "None serialized"
    written = ", ".join(f"`{compact_name(x)}`" for x in packet.get("written_members", [])) or "None serialized"
    stale = ", ".join(f"`{compact_name(x)}`" for x in packet.get("potentially_stale_members", [])) or "None serialized"
    writer = packet.get("writer_block", {})
    lines = [
        f"# {packet['review_id']} · Subject {packet.get('subject', '')}", "",
        "## Candidate in one view", "",
        "| Question | Serialized evidence |", "|---|---|",
        f"| What state is related? | {relation} |",
        f"| What does the transition write? | {written} |",
        f"| What may be left stale? | {stale} |", "",
        "## Candidate execution", "",
        f"1. **Partial transition:** `{short_function(packet.get('writer_owner'))}` reaches `{short_function(writer.get('function_key'))}`, which writes {written}.",
    ]
    grouped = grouped_consumption(packet)
    if grouped:
        lines.append("2. **Later consumption:**")
        for member, item in sorted(grouped.items()):
            readers = sorted(item["readers"])
            shown = "; ".join(readers[:3])
            more = f"; plus {len(readers)-3} other read site(s)" if len(readers) > 3 else ""
            sinks = "; ".join(sorted(item["sinks"])) or "no modeled sink serialized"
            lines.append(f"   - `{member}` is read at {shown}{more}, reaching {sinks}.")
        context_count = len(set().union(*(x["contexts"] for x in grouped.values())))
        writer_first = any(a is True for x in grouped.values() for a, _ in x["orders"])
        lines.append(f"3. **Feasibility context:** evidence spans {context_count} entry context(s). Serialized same-graph writer-to-reader reachability is {'present' if writer_first else 'not present; cross-call or cross-transaction ordering must therefore be judged from the code'}.")
    else:
        lines.append("2. **Later consumption:** no reader witness was serialized.")

    origins = packet.get("structural_claim", {}).get("origin_sites", [])
    if origins:
        expressions = "; ".join(f"`{o.get('expression', '')}` in `{short_function(o.get('function_key'))}`" for o in origins)
        lines += ["", "## Why these values were linked", "", expressions]

    excerpts = choose_excerpts(packet)
    if excerpts:
        lines += ["", "## Most relevant source evidence", ""]
        for excerpt in excerpts:
            lines += [f"**`{excerpt.get('file')}` · lines {excerpt.get('start_line', '?')}–{excerpt.get('end_line', '?')}**", "", "```solidity", excerpt["source"].rstrip(), "```", ""]

    lines += [
        f"[Open the complete evidence appendix](../evidence/{packet['review_id']}.md)", "",
        "## Decision", "", "| Field | Entry |", "|---|---|",
        "| C1 |  |", "| C2 |  |", "| C3 |  |", "| C4 |  |", "| C5 |  |",
        "| Label |  |", "| NONBUG cause |  |", "| Evidence note |  |", "",
    ]
    return "\n".join(lines)


def evidence_appendix(packet):
    text = make_card(packet)
    decision = text.find("## Decision")
    if decision >= 0:
        text = text[:decision]
    return f"# {packet['review_id']} · Complete evidence appendix\n\n[Back to the readable card](../cards/{packet['review_id']}.md)\n\n" + text.split("\n", 2)[-1].rstrip() + "\n"


def main():
    source, destination = map(Path, sys.argv[1:3])
    cards = destination / "cards"
    cards.mkdir(parents=True, exist_ok=True)
    evidence = destination / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader((source / "web3bugs_agreement.csv").open(newline="")))
    for row in rows:
        packet = json.loads((source / row["packet"]).read_text())
        (cards / f"{row['review_id']}.md").write_text(readable_card(packet))
        (evidence / f"{row['review_id']}.md").write_text(evidence_appendix(packet))
    shutil.copy2(source / "web3bugs_agreement.csv", destination / "web3bugs_agreement.csv")
    shutil.copy2(source / "WEB3BUGS_GUIDE.md", destination / "WEB3BUGS_GUIDE.md")
    index = ["# Web3Bugs agreement-review cards", "", "Read `WEB3BUGS_GUIDE.md`, then review the concise cards in `cards/`. Each card links to its complete evidence appendix only when more detail is needed. Record final decisions in `web3bugs_agreement.csv`.", "", "## Cards", ""]
    index += [f"- [{r['review_id']}](cards/{r['review_id']}.md) · subject {r['subject']}" for r in rows]
    (destination / "README.md").write_text("\n".join(index) + "\n")
    print(f"wrote {len(rows)} cards to {destination}")


if __name__ == "__main__":
    main()
