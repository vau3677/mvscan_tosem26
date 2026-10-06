#!/usr/bin/env python3
import csv
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote


WEB3BUGS_REPOSITORY = "https://github.com/ZhangZhuoSJTU/Web3Bugs"
SOURCE_MAP = {}


def code(value):
    text = str(value if value not in (None, "") else "not serialized")
    return "`" + text.replace("`", "ˋ") + "`"


def short_function(value):
    return str(value or "not serialized").split("::")[-1]


def compact_function(value):
    text = short_function(value)
    if len(text) <= 72 or "(" not in text:
        return text
    return text.split("(", 1)[0] + "(…)"


def revision(packet):
    return packet.get("structural_claim", {}).get("revision_role") or "fd8544e84f0d6cea4b4d6a44ee62d8f7623648f4"


def subject_root_url(packet):
    return f"{WEB3BUGS_REPOSITORY}/tree/{revision(packet)}/contracts/{quote(str(packet.get('subject', '')), safe='')}"


def source_url(packet, path, line=None, end_line=None):
    subject = str(packet.get("subject"))
    entry = SOURCE_MAP.get(f"{subject}|{path}")
    if not entry or not entry.get("path"):
        return subject_root_url(packet)
    relative = f"contracts/{subject}/{entry['path']}"
    url = f"{WEB3BUGS_REPOSITORY}/blob/{revision(packet)}/{quote(relative, safe='/@._-')}"
    if line:
        url += f"#L{line}"
        if end_line and end_line != line:
            url += f"-L{end_line}"
    return url


def relation_members(packet):
    relation = packet.get("relation", [])
    return relation.get("members", []) if isinstance(relation, dict) else relation


def entity_parts(value):
    if isinstance(value, dict):
        key = value.get("entity_key") or []
        return {
            "name": value.get("name") or (key[-1] if key else "unnamed entity"),
            "kind": value.get("kind") or (key[0] if key else "state"),
            "file": key[1] if len(key) > 1 else "",
            "key": value.get("key") or (key[3] if len(key) > 3 else ""),
        }
    if isinstance(value, list):
        return {
            "name": value[-1] if value else "unnamed entity",
            "kind": value[0] if value else "state",
            "file": value[1] if len(value) > 1 else "",
            "key": value[3] if len(value) > 3 else "",
        }
    return {"name": str(value), "kind": "state", "file": "", "key": ""}


def entity_id(value):
    part = entity_parts(value)
    return (part["kind"], part["file"], part["name"], part["key"])


def entity_line(value):
    part = entity_parts(value)
    kind = {"SV": "state variable", "MS": "mapping slot", "state": "state variable", "mapping_slot": "mapping slot"}.get(str(part["kind"]), str(part["kind"]).replace("_", " "))
    qualifiers = [kind]
    if part["file"]:
        qualifiers.append(str(part["file"]))
    if part["key"]:
        qualifiers.append("key " + str(part["key"]))
    return f"- {code(part['name'])}  \n  " + " · ".join(qualifiers)


def unique_entities(values):
    seen, result = set(), []
    for value in values:
        key = entity_id(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def render_entities(values):
    values = unique_entities(values)
    return "\n".join(entity_line(value) for value in values) if values else "- No entity was serialized."


def witness_summary(packet):
    groups = defaultdict(lambda: {
        "read_sites": set(), "sinks": set(), "contexts": set(),
        "writer_to_reader": [], "reader_to_writer": [], "constraints": set(),
    })
    for witness in packet.get("reader_witnesses", []):
        reader = witness.get("reader", {})
        block = reader.get("block", {})
        site = (
            short_function(reader.get("signature") or block.get("function_key")),
            reader.get("file") or "file not serialized",
            reader.get("line") if reader.get("line") is not None else "line not serialized",
            block.get("node_id") if block.get("node_id") is not None else "node not serialized",
        )
        members = []
        for relation in witness.get("relation_evidence", []):
            member = relation.get("reader_member") or relation.get("reader_location")
            if member:
                members.append(member)
            for constraint in relation.get("key_constraints", []):
                groups[entity_id(member) if member else ("unknown", "", "unknown", "")]["constraints"].add(json.dumps(constraint, sort_keys=True))
        if not members:
            members = ["omitted state not identified"]
        for member in unique_entities(members):
            group = groups[entity_id(member)]
            group["entity"] = member
            group["read_sites"].add(site)
            for sink in witness.get("sinks", []):
                group["sinks"].add((sink.get("kind") or "kind not serialized", short_function(sink.get("function_key")), sink.get("node_id")))
            owner = reader.get("context", {}).get("owner")
            if owner:
                group["contexts"].add(short_function(owner))
            group["writer_to_reader"].append(witness.get("writer_reaches_reader"))
            group["reader_to_writer"].append(witness.get("reader_reaches_writer"))
    return groups


def reachability(values):
    yes = sum(value is True for value in values)
    no = sum(value is False for value in values)
    unknown = len(values) - yes - no
    pieces = []
    if yes:
        pieces.append(f"present in {yes} witness{'es' if yes != 1 else ''}")
    if no:
        pieces.append(f"absent in {no} witness{'es' if no != 1 else ''}")
    if unknown:
        pieces.append(f"unspecified in {unknown}")
    return "; ".join(pieces) or "not serialized"


def source_blocks(packet):
    seen, blocks = set(), []
    for excerpt in packet.get("source_excerpts", []):
        if excerpt.get("status", "AVAILABLE") != "AVAILABLE" or not excerpt.get("source"):
            continue
        key = (excerpt.get("file"), excerpt.get("start_line"), excerpt.get("end_line"), excerpt.get("source"))
        if key not in seen:
            seen.add(key)
            blocks.append(excerpt)
    return blocks


def quick_consumption(groups):
    lines = []
    for group in groups.values():
        part = entity_parts(group["entity"])
        sites = sorted(group["read_sites"])
        sinks = sorted(group["sinks"])
        site_text = "; ".join(f"{compact_function(name)} ({file}:{line})" for name, file, line, _ in sites[:2])
        if len(sites) > 2:
            site_text += f"; {len(sites) - 2} more read site(s) below"
        sink_kinds = ", ".join(sorted({kind.replace("_", " ") for kind, _, _ in sinks})) or "no sink serialized"
        lines.append(f"- {code(part['name'])}: read at {site_text}; reaches {sink_kinds}.")
    return "\n".join(lines) if lines else "- No omitted-state read witness was serialized."


def make_card(packet):
    review_id = packet["review_id"]
    related = unique_entities(relation_members(packet))
    written = unique_entities(packet.get("written_members", []))
    stale = unique_entities(packet.get("potentially_stale_members", []))
    writer = packet.get("writer_block", {})
    groups = witness_summary(packet)
    excerpts = source_blocks(packet)
    lines = [
        f"# {review_id} — Subject {packet.get('subject', '')}", "",
        f"**Frozen source:** [Open Web3Bugs subject {packet.get('subject', '')}]({subject_root_url(packet)})", "",
        "## Quick scan", "",
        "### State relationship", "",
        f"The detector groups **{len(related)} persistent state entities** as a candidate relationship:", "",
        render_entities(related), "",
        "### Reported partial transition", "",
        f"**Entry context:** {code(compact_function(packet.get('writer_owner')))}  ",
        f"**Write block:** {code(compact_function(writer.get('function_key')))}", "",
        "**Written in the reported block**", "", render_entities(written), "",
        "**Related state reported as potentially stale**", "", render_entities(stale), "",
        "### Reported later use", "", quick_consumption(groups), "",
        "## Evidence to inspect", "",
    ]
    origins = packet.get("structural_claim", {}).get("origin_sites", [])
    if origins:
        lines += ["### Relation evidence", ""]
        for origin in origins:
            lines.append(f"- Expression {code(origin.get('expression'))} in {code(short_function(origin.get('function_key')))}")
        lines.append("")
    constraints = packet.get("structural_claim", {}).get("key_equality_constraints", [])
    if constraints:
        lines += ["**Key constraints**", ""] + [f"- {code(json.dumps(item, ensure_ascii=False, sort_keys=True))}" for item in constraints] + [""]

    lines += ["### Omitted-state reads and sinks", ""]
    if not groups:
        lines += ["No reader witness was serialized.", ""]
    for group in groups.values():
        part = entity_parts(group["entity"])
        lines += ["<details>", f"<summary>{part['name']}: {len(group['read_sites'])} read site(s), {len(group['sinks'])} sink(s)</summary>", "", "**Read sites**", ""]
        for name, file, line, node in sorted(group["read_sites"]):
            location = f"[{file}:{line}]({source_url(packet, file, line if isinstance(line, int) else None)})"
            lines.append(f"- {code(name)} — {location} (detector node {node})")
        lines += ["", "**Modeled behavioral sinks**", ""]
        for kind, function, node in sorted(group["sinks"]):
            suffix = f" (detector node {node})" if node is not None else ""
            lines.append(f"- {kind.replace('_', ' ')} in {code(function)}{suffix}")
        if not group["sinks"]:
            lines.append("- No sink was serialized.")
        lines += ["", "**Ordering evidence**", "",
                  f"- Direct writer → reader reachability: {reachability(group['writer_to_reader'])}",
                  f"- Reverse reader → writer reachability: {reachability(group['reader_to_writer'])}", ""]
        lines += [f"**Execution contexts ({len(group['contexts'])})**", ""]
        lines += [f"- {code(value)}" for value in sorted(group["contexts"])] or ["- None serialized."]
        lines += ["", "</details>", ""]

    lines += [f"### Source excerpts ({len(excerpts)})", ""]
    for index, excerpt in enumerate(excerpts, 1):
        link = source_url(packet, excerpt.get("file"), excerpt.get("start_line"), excerpt.get("end_line"))
        lines += ["<details>", f"<summary>Excerpt {index}: {excerpt.get('file')} lines {excerpt.get('start_line', '?')}–{excerpt.get('end_line', '?')}</summary>", "", f"[Open this file at the frozen revision]({link})", "", "````solidity", excerpt["source"].rstrip(), "````", "", "</details>", ""]

    lines += [
        "## Decision", "",
        "- **C1:**", "- **C2:**", "- **C3:**", "- **C4:**", "- **C5:**",
        "- **Label:**", "- **NONBUG primary cause:**", "- **Evidence note:**", "",
    ]
    return "\n".join(lines)


def validate_card(packet, text):
    errors = []
    if text.count("<details>") != text.count("</details>"):
        errors.append("unbalanced details blocks")
    if text.count("````solidity") != len(source_blocks(packet)) or text.count("\n````\n") != len(source_blocks(packet)):
        errors.append("unbalanced source fences")
    if packet.get("global_candidate_id") and packet["global_candidate_id"] in text:
        errors.append("internal candidate hash leaked")
    if subject_root_url(packet) not in text:
        errors.append("missing frozen subject link")
    for value in relation_members(packet) + packet.get("written_members", []) + packet.get("potentially_stale_members", []):
        if str(entity_parts(value)["name"]) not in text:
            errors.append(f"missing entity {entity_parts(value)['name']}")
    for witness in packet.get("reader_witnesses", []):
        reader = witness.get("reader", {})
        expected = short_function(reader.get("signature") or reader.get("block", {}).get("function_key"))
        if expected not in text:
            errors.append(f"missing reader {expected}")
        for sink in witness.get("sinks", []):
            expected = short_function(sink.get("function_key"))
            if expected not in text:
                errors.append(f"missing sink {expected}")
    for excerpt in source_blocks(packet):
        if excerpt["source"].rstrip() not in text:
            errors.append(f"missing source excerpt {excerpt.get('file')}:{excerpt.get('start_line')}")
        if source_url(packet, excerpt.get("file"), excerpt.get("start_line"), excerpt.get("end_line")) not in text:
            errors.append(f"missing source link {excerpt.get('file')}:{excerpt.get('start_line')}")
    if any(token in text for token in ("[object Object]", "undefined", "None")):
        errors.append("placeholder-like rendering")
    return errors


def main():
    global SOURCE_MAP
    source, destination = map(Path, sys.argv[1:3])
    if len(sys.argv) < 4:
        raise SystemExit("verified source-map JSON is required")
    SOURCE_MAP = json.loads(Path(sys.argv[3]).read_text())
    cards = destination / "cards"
    cards.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader((source / "web3bugs_agreement.csv").open(newline="")))
    failures = []
    for row in rows:
        packet = json.loads((source / row["packet"]).read_text())
        text = make_card(packet)
        errors = validate_card(packet, text)
        if errors:
            failures.append((row["review_id"], errors))
        (cards / f"{row['review_id']}.md").write_text(text)
    if failures:
        raise SystemExit("card validation failed: " + repr(failures[:10]))
    shutil.copy2(source / "web3bugs_agreement.csv", destination / "web3bugs_agreement.csv")
    shutil.copy2(source / "WEB3BUGS_GUIDE.md", destination / "WEB3BUGS_GUIDE.md")
    readme = [
        "# Web3Bugs agreement-review cards", "",
        "Read `WEB3BUGS_GUIDE.md`, then open the files in `cards/` in review-ID order. Each card begins with a short scan, links to the frozen Web3Bugs source, and keeps complete supporting evidence in collapsible sections. Record final decisions in `web3bugs_agreement.csv`.", "",
        "## Cards", "",
    ] + [f"- [{row['review_id']}](cards/{row['review_id']}.md) — subject {row['subject']}" for row in rows]
    (destination / "README.md").write_text("\n".join(readme) + "\n")
    print(f"generated and validated {len(rows)} cards")


if __name__ == "__main__":
    main()
