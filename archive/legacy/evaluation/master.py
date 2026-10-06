#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, dataclasses, json, re, statistics, zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
EXPECTED_HEADER = ["Ablation", "Finding", "Code4rena Report", "Type", "Comments"]
FILL_LOG_SHEET = "B0_FILL_LOG"
ABLATIONS_ORDER = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]
EXPECTED_WORKBOOK_ABLATIONS = {"B0", "B1", "B2", "B3", "B4", "B6"}
EXCLUSION_PRIORITY = ["mock", "test", "out_of_scope", "other", "unlabeled"]
SCORED_TYPES = {"TP", "FP", "ZD"}
SCAN_RE = re.compile(r"(?P<contracts>\d+)c/\d+/(?P<findings>\d+)r")

@dataclass(frozen=True)
class ExtractedRow:
    sheet: str
    row_idx: int
    ablation: str
    finding_text: str
    code4rena: str
    type_raw: str
    comments: str

@dataclass(frozen=True)
class NormalizedRow:
    sheet: str
    row_idx: int
    ablation: str
    finding_header: str
    finding_text: str
    finding_kind: str
    type_raw: str
    type_class: str
    exclusion_reason: str
    code4rena: str
    comments: str
    finding_key: str

def _strip_text(value) -> str:
    if value is None: return ""
    return str(value).replace("\u2028", "\n").replace("\xa0", " ").strip()

def _col_to_num(col: str) -> int:
    value = 0
    for ch in col: value = value * 26 + (ord(ch) - 64)
    return value

def _parse_ref(ref: str) -> Tuple[int, int]:
    match = re.match(r"([A-Z]+)(\d+)", ref)
    if not match: raise ValueError(f"Unrecognized cell reference: {ref}")
    return _col_to_num(match.group(1)), int(match.group(2))

def _read_shared_strings(zf: zipfile.ZipFile) -> List[str]:
    if "xl/sharedStrings.xml" not in zf.namelist(): return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    shared: List[str] = []
    for si in root.findall(f"{{{NS_MAIN}}}si"):
        pieces: List[str] = []
        for tnode in si.iter(f"{{{NS_MAIN}}}t"):
            pieces.append(tnode.text or "")
        shared.append("".join(pieces))
    return shared

def _cell_text(cell: ET.Element, shared: List[str]) -> str:
    cell_type = cell.attrib.get("t")
    value_node = cell.find(f"{{{NS_MAIN}}}v")
    if value_node is None:
        inline = cell.find(f"{{{NS_MAIN}}}is/{{{NS_MAIN}}}t")
        return _strip_text(inline.text if inline is not None else "")
    raw = value_node.text
    if cell_type == "s" and raw is not None:
        idx = int(raw)
        if idx < 0 or idx >= len(shared):
            raise ValueError(f"sharedStrings index out of range: {idx}")
        return _strip_text(shared[idx])
    return _strip_text(raw)

def _workbook_sheets(zf: zipfile.ZipFile) -> List[Tuple[str, str]]:
    workbook = ET.fromstring(zf.read("xl/workbook.xml"))
    rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rid_to_target: Dict[str, str] = {}
    for rel in rels.findall(f"{{{NS_PKG_REL}}}Relationship"):
        rid_to_target[rel.attrib["Id"]] = rel.attrib["Target"]

    sheets: List[Tuple[str, str]] = []
    for sheet in workbook.findall(f"{{{NS_MAIN}}}sheets/{{{NS_MAIN}}}sheet"):
        name = sheet.attrib["name"]
        rid = sheet.attrib[f"{{{NS_REL}}}id"]
        target = rid_to_target[rid]
        if not target.startswith("xl/"):
            target = f"xl/{target}"
        sheets.append((name, target))
    return sheets

def _parse_sheet_rows(zf: zipfile.ZipFile, target: str, shared: List[str]) -> Dict[int, Dict[int, str]]:
    sheet_root = ET.fromstring(zf.read(target))
    rows: Dict[int, Dict[int, str]] = {}
    for row in sheet_root.findall(f".//{{{NS_MAIN}}}sheetData/{{{NS_MAIN}}}row"):
        row_idx = int(row.attrib.get("r", "0"))
        cells: Dict[int, str] = {}
        for cell in row.findall(f"{{{NS_MAIN}}}c"):
            ref = cell.attrib.get("r", "")
            col_idx, _ = _parse_ref(ref)
            cells[col_idx] = _cell_text(cell, shared)
        if cells: rows[row_idx] = cells
    return rows

def extract_rows(xlsx_path: str | Path) -> List[ExtractedRow]:
    path = Path(xlsx_path)
    if not path.exists(): raise FileNotFoundError(f"Workbook not found: {path}")

    extracted: List[ExtractedRow] = []
    with zipfile.ZipFile(path) as zf:
        shared = _read_shared_strings(zf)
        for sheet_name, target in _workbook_sheets(zf):
            if sheet_name == FILL_LOG_SHEET: continue
            rows = _parse_sheet_rows(zf, target, shared)
            header = [rows.get(1, {}).get(idx, "") for idx in range(1, 6)]
            if header != EXPECTED_HEADER:
                raise ValueError(f"Header mismatch in sheet '{sheet_name}': expected {EXPECTED_HEADER}, got {header}")

            for row_idx in sorted(rows):
                if row_idx == 1:
                    continue
                cells = rows[row_idx]
                values = {
                    "ablation": cells.get(1, ""),
                    "finding_text": cells.get(2, ""),
                    "code4rena": cells.get(3, ""),
                    "type_raw": cells.get(4, ""),
                    "comments": cells.get(5, ""),
                }
                if not any(values.values()):
                    continue
                extracted.append(
                    ExtractedRow(
                        sheet=sheet_name,
                        row_idx=row_idx,
                        ablation=values["ablation"],
                        finding_text=values["finding_text"],
                        code4rena=values["code4rena"],
                        type_raw=values["type_raw"],
                        comments=values["comments"],
                    )
                )
    return extracted

def _normalize_type(type_raw: str) -> str: return (type_raw or "").strip().upper()

def _finding_header(finding_text: str) -> str:
    if not finding_text: return ""
    return finding_text.split("\n", 1)[0].strip()

def _finding_kind(header: str) -> str:
    if not header: return "<NONE>"
    bracket = re.match(r"^\[([^\]]+)\]", header)
    if bracket: return bracket.group(1).strip()
    near = re.match(r"^([a-z_]+)\]", header)
    if near: return near.group(1).strip()
    return "<UNPARSED>"

def _exclusion_reason(normalized_type: str, comments: str) -> str:
    if normalized_type == "": return "unlabeled"
    text = (comments or "").strip().lower()
    if "mock" in text and "not counted" in text: return "mock"
    if "test" in text and "not counted" in text: return "test"
    if "out of scope" in text: return "out_of_scope"
    return "other"

def classify_rows(rows: List[ExtractedRow]) -> List[NormalizedRow]:
    classified: List[NormalizedRow] = []
    for row in rows:
        normalized_type = _normalize_type(row.type_raw)
        header = _finding_header(row.finding_text)
        kind = _finding_kind(header)
        ablation = (row.ablation or "").strip().upper()

        if normalized_type in SCORED_TYPES:
            type_class = f"scored_{normalized_type.lower()}"
            exclusion_reason = ""
        else:
            exclusion_reason = _exclusion_reason(normalized_type, row.comments)
            type_class = "excluded_unlabeled" if exclusion_reason == "unlabeled" else "excluded_nonlabel"
        classified.append(NormalizedRow(
            sheet=row.sheet,
            row_idx=row.row_idx,
            ablation=ablation,
            finding_header=header,
            finding_text=row.finding_text,
            finding_kind=kind,
            type_raw=row.type_raw,
            type_class=type_class,
            exclusion_reason=exclusion_reason,
            code4rena=row.code4rena,
            comments=row.comments,
            finding_key=f"{row.sheet}::{header}",
        ))
    return classified

def _resolved_exclusion_reason(reasons: Sequence[str]) -> str:
    reason_set = {r for r in reasons if r}
    for candidate in EXCLUSION_PRIORITY:
        if candidate in reason_set: return candidate
    return "unlabeled"

def _precision(tp: int, zd: int, fp: int):
    denom = tp + zd + fp
    if denom == 0: return None
    return (tp + zd) / denom

def aggregate_tables(rows: List[NormalizedRow]) -> Dict[str, List[Dict[str, object]]]:
    seen_ablations = {row.ablation for row in rows if row.ablation}
    unknown = sorted(seen_ablations - set(ABLATIONS_ORDER))
    if unknown: raise ValueError(f"Unknown ablation values in workbook rows: {unknown}")
    missing_expected = sorted(EXPECTED_WORKBOOK_ABLATIONS - seen_ablations)
    if missing_expected:
        raise ValueError(
            "Workbook is missing expected ablation values. "
            f"Expected at least {sorted(EXPECTED_WORKBOOK_ABLATIONS)}, missing {missing_expected}"
        )

    groups: Dict[str, Dict[str, List[NormalizedRow]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row.ablation: groups[row.ablation][row.finding_key].append(row)

    resolutions: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for ablation in sorted(groups):
        for finding_key, key_rows in groups[ablation].items():
            scored_labels_set = set()
            exclusion_reasons: List[str] = []
            row_indices: List[int] = []
            type_values: List[str] = []

            for row in key_rows:
                row_indices.append(row.row_idx)
                type_values.append((row.type_raw or "").strip() or "<BLANK>")
                if row.type_class == "scored_tp": scored_labels_set.add("TP")
                elif row.type_class == "scored_fp": scored_labels_set.add("FP")
                elif row.type_class == "scored_zd": scored_labels_set.add("ZD")
                else: exclusion_reasons.append(row.exclusion_reason)

            scored_labels = sorted(scored_labels_set)
            first = key_rows[0]

            if scored_labels:
                if "FP" in scored_labels_set: resolved_label = "FP"
                elif "TP" in scored_labels_set: resolved_label = "TP"
                else: resolved_label = "ZD"
                exclusion_reason = ""
            else:
                resolved_label = "EXCLUDED"
                exclusion_reason = _resolved_exclusion_reason(exclusion_reasons)

            resolutions[ablation].append({
                "ablation": ablation,
                "finding_key": finding_key,
                "sheet": first.sheet,
                "finding_header": first.finding_header,
                "finding_kind": first.finding_kind,
                "resolved_label": resolved_label,
                "exclusion_reason": exclusion_reason,
                "scored_labels": scored_labels,
                "row_count": len(key_rows),
                "row_indices": sorted(row_indices),
                "type_values": sorted(set(type_values)),
            })

    if "B5" not in resolutions: resolutions["B5"] = []

    kinds = sorted({row.finding_kind for row in rows if row.finding_kind})
    if not kinds: kinds = ["<NONE>"]

    master_ablation_rows: List[Dict[str, object]] = []
    master_by_kind_rows: List[Dict[str, object]] = []
    master_exclusions_rows: List[Dict[str, object]] = []
    master_conflicts_rows: List[Dict[str, object]] = []
    positive_union = set()
    raw_nonlabel_rows = defaultdict(int)

    for row in rows:
        if row.ablation and row.type_class.startswith("excluded"):
            raw_nonlabel_rows[row.ablation] += 1

    for ablation in ABLATIONS_ORDER:
        resolved = resolutions.get(ablation, [])
        tp = sum(1 for item in resolved if item["resolved_label"] == "TP")
        zd = sum(1 for item in resolved if item["resolved_label"] == "ZD")
        fp = sum(1 for item in resolved if item["resolved_label"] == "FP")
        scored_total = tp + zd + fp
        semantic_total = len(resolved)

        excluded_mock = sum(1 for item in resolved if item["resolved_label"] == "EXCLUDED" and item["exclusion_reason"] == "mock")
        excluded_test = sum(1 for item in resolved if item["resolved_label"] == "EXCLUDED" and item["exclusion_reason"] == "test")
        excluded_out = sum(1 for item in resolved if item["resolved_label"] == "EXCLUDED" and item["exclusion_reason"] == "out_of_scope")
        excluded_other = sum(1 for item in resolved if item["resolved_label"] == "EXCLUDED" and item["exclusion_reason"] == "other")
        excluded_unlabeled = sum(1 for item in resolved if item["resolved_label"] == "EXCLUDED" and item["exclusion_reason"] == "unlabeled")
        excluded_total = excluded_mock + excluded_test + excluded_out + excluded_other + excluded_unlabeled

        if semantic_total != scored_total + excluded_total:
            raise AssertionError(f"Reconciliation failed for {ablation}: semantic_total={semantic_total}, scored_total={scored_total}, excluded_total={excluded_total}")

        p = _precision(tp=tp, zd=zd, fp=fp)
        master_ablation_rows.append({
            "ablation": ablation,
            "semantic_total": semantic_total,
            "scored_total": scored_total,
            "tp": tp,
            "zd": zd,
            "fp": fp,
            "precision_tp_plus_zd": "" if p is None else f"{p:.12f}",
            "excluded_total": excluded_total,
            "excluded_mock": excluded_mock,
            "excluded_test": excluded_test,
            "excluded_out_of_scope": excluded_out,
            "excluded_other": excluded_other,
            "excluded_unlabeled": excluded_unlabeled,
        })

        master_exclusions_rows.append({
            "ablation": ablation,
            "excluded_total_keys": excluded_total,
            "excluded_mock_keys": excluded_mock,
            "excluded_test_keys": excluded_test,
            "excluded_out_of_scope_keys": excluded_out,
            "excluded_other_keys": excluded_other,
            "excluded_unlabeled_keys": excluded_unlabeled,
            "excluded_nonlabel_rows_raw": raw_nonlabel_rows.get(ablation, 0),
        })

        for item in resolved:
            if item["resolved_label"] in {"TP", "ZD"}:
                positive_union.add(item["finding_key"])
            if len(item["scored_labels"]) > 1:
                master_conflicts_rows.append({
                    "ablation": ablation,
                    "finding_key": item["finding_key"],
                    "sheet": item["sheet"],
                    "finding_header": item["finding_header"],
                    "finding_kind": item["finding_kind"],
                    "scored_labels": "|".join(item["scored_labels"]),
                    "resolved_label": item["resolved_label"],
                    "row_count": item["row_count"],
                    "row_indices": "|".join(str(v) for v in item["row_indices"]),
                    "type_values": "|".join(item["type_values"]),
                })

        by_kind = defaultdict(lambda: {"tp": 0, "zd": 0, "fp": 0})
        for item in resolved:
            if item["resolved_label"] == "TP": by_kind[item["finding_kind"]]["tp"] += 1
            elif item["resolved_label"] == "ZD": by_kind[item["finding_kind"]]["zd"] += 1
            elif item["resolved_label"] == "FP": by_kind[item["finding_kind"]]["fp"] += 1

        for kind in kinds:
            k_tp = by_kind[kind]["tp"]
            k_zd = by_kind[kind]["zd"]
            k_fp = by_kind[kind]["fp"]
            k_total = k_tp + k_zd + k_fp
            k_precision = _precision(tp=k_tp, zd=k_zd, fp=k_fp)
            master_by_kind_rows.append({
                "ablation": ablation,
                "finding_kind": kind,
                "scored_total": k_total,
                "tp": k_tp,
                "zd": k_zd,
                "fp": k_fp,
                "precision_tp_plus_zd": "" if k_precision is None else f"{k_precision:.12f}",
            })

    union_total = len(positive_union)
    master_union_rows: List[Dict[str, object]] = []
    for ablation in ABLATIONS_ORDER:
        resolved = resolutions.get(ablation, [])
        positives = {item["finding_key"] for item in resolved if item["resolved_label"] in {"TP", "ZD"}}
        coverage = (len(positives) / union_total) if union_total else None
        master_union_rows.append({
            "ablation": ablation,
            "positive_keys": len(positives),
            "union_positive_keys": union_total,
            "coverage_vs_union_positive": "" if coverage is None else f"{coverage:.12f}",
        })

    return {
        "master_ablation_table": master_ablation_rows,
        "master_by_kind": master_by_kind_rows,
        "master_exclusions": master_exclusions_rows,
        "master_conflicts": master_conflicts_rows,
        "master_union_coverage": master_union_rows,
    }


def load_ablation_map(ablation_map_path: str | Path) -> Dict[str, Dict[str, object]]:
    path = Path(ablation_map_path)
    if not path.exists(): raise FileNotFoundError(f"Ablation map not found: {path}")

    mapping: Dict[str, Dict[str, object]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh: lines = [line.rstrip("\n") for line in fh]
    if not lines: raise ValueError(f"Ablation map is empty: {path}")

    header = lines[0].split("\t")
    if header[:3] != ["id", "name", "env_json"]:
        raise ValueError(f"Unexpected ablation map header: {header[:3]} (expected ['id', 'name', 'env_json'])")

    for line in lines[1:]:
        if not line.strip(): continue
        parts = line.split("\t")
        if len(parts) < 3: raise ValueError(f"Malformed ablation map row: {line}")
        ablation_id = int(parts[0].strip())
        name = parts[1].strip()
        env_json = parts[2].strip()
        env = json.loads(env_json) if env_json else {}
        mapping[name] = {
            "ablation_id": ablation_id,
            "ablation_name": f"B{ablation_id}",
            "config_name": name,
            "env": env,
        }

    if not mapping: raise ValueError("No ablation rows found in ablation map")
    return mapping


def compute_runtime_summary(results_tsv_path: str | Path, ablation_map_path: str | Path) -> List[Dict[str, object]]:
    ablation_map = load_ablation_map(ablation_map_path)
    path = Path(results_tsv_path)
    if not path.exists(): raise FileNotFoundError(f"results.tsv not found: {path}")

    by_ablation: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip(): continue
            if line.lower().startswith("repo") and "ablation" in line.lower(): continue

            parts = line.split("\t")
            if len(parts) < 5: raise ValueError(f"Malformed results row: {line}")

            repo = parts[0].strip()
            ablation_config = parts[1].strip()
            scan_summary = parts[2].strip()
            elapsed_s = float(parts[3].strip())
            rc = parts[4].strip()

            if ablation_config not in ablation_map:
                raise ValueError(f"results.tsv ablation '{ablation_config}' not found in ablation map")

            match = SCAN_RE.search(scan_summary)
            if not match: raise ValueError(f"Unable to parse contracts/findings from: '{scan_summary}'")
            contracts = int(match.group("contracts"))
            findings = int(match.group("findings"))

            by_ablation[ablation_config].append({
                "repo": repo,
                "elapsed_s": elapsed_s,
                "contracts": contracts,
                "findings": findings,
                "scan_summary": scan_summary,
                "rc": rc,
            })

    if not by_ablation: raise ValueError("No runtime rows parsed from results.tsv")

    summary_rows: List[Dict[str, object]] = []
    for config_name, info in sorted(ablation_map.items(), key=lambda kv: kv[1]["ablation_id"]):
        rows = by_ablation.get(config_name, [])
        if not rows:
            summary_rows.append({
                "ablation_id": info["ablation_id"],
                "ablation_name": info["ablation_name"],
                "config_name": config_name,
                "repos_total": 0,
                "repos_nonempty": 0,
                "contracts_total": 0,
                "wallclock_sum_s": "0.000000",
                "mean_repo_s": "",
                "median_repo_s": "",
                "sec_per_contract": "",
            })
            continue

        elapsed = [r["elapsed_s"] for r in rows]
        contracts_total = sum(r["contracts"] for r in rows)
        wallclock_sum = sum(elapsed)
        summary_rows.append({
            "ablation_id": info["ablation_id"],
            "ablation_name": info["ablation_name"],
            "config_name": config_name,
            "repos_total": len(rows),
            "repos_nonempty": sum(1 for r in rows if r["findings"] > 0),
            "contracts_total": contracts_total,
            "wallclock_sum_s": f"{wallclock_sum:.6f}",
            "mean_repo_s": f"{statistics.mean(elapsed):.6f}",
            "median_repo_s": f"{statistics.median(elapsed):.6f}",
            "sec_per_contract": f"{(wallclock_sum / contracts_total):.12f}" if contracts_total else "",
        })
    return summary_rows

def _write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: Sequence[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows: writer.writerow({name: row.get(name, "") for name in fieldnames})

def _write_normalized_rows_csv(path: Path, rows: List[NormalizedRow]):
    data = [dataclasses.asdict(row) for row in sorted(rows, key=lambda r: (r.ablation, r.sheet, r.row_idx, r.finding_key))]
    _write_csv(path, data, [
        "sheet",
        "row_idx",
        "ablation",
        "finding_header",
        "finding_text",
        "finding_kind",
        "type_raw",
        "type_class",
        "exclusion_reason",
        "code4rena",
        "comments",
        "finding_key",
    ])

def main():
    parser = argparse.ArgumentParser(description="Single-file generator for MV-SCAN normalized/master/runtime CSV outputs.")
    parser.add_argument("--xlsx", required=True, help="Path to workbook .xlsx")
    parser.add_argument("--results", required=True, help="Path to results.tsv")
    parser.add_argument("--ablation-map", required=True, help="Path to out/ablation_map.tsv")
    parser.add_argument("--out", required=True, help="Output directory")
    args = parser.parse_args()

    xlsx = Path(args.xlsx).resolve()
    results = Path(args.results).resolve()
    ablation_map = Path(args.ablation_map).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    normalized_rows = classify_rows(extract_rows(xlsx))
    tables = aggregate_tables(normalized_rows)
    runtime_rows = compute_runtime_summary(results, ablation_map)

    _write_normalized_rows_csv(out_dir / "normalized_rows.csv", normalized_rows)
    _write_csv(out_dir / "master_ablation_table.csv", tables["master_ablation_table"], [
        "ablation",
        "semantic_total",
        "scored_total",
        "tp",
        "zd",
        "fp",
        "precision_tp_plus_zd",
        "excluded_total",
        "excluded_mock",
        "excluded_test",
        "excluded_out_of_scope",
        "excluded_other",
        "excluded_unlabeled",
    ])
    _write_csv(out_dir / "master_by_kind.csv", tables["master_by_kind"], ["ablation", "finding_kind", "scored_total", "tp", "zd", "fp", "precision_tp_plus_zd"])
    _write_csv(out_dir / "master_exclusions.csv", tables["master_exclusions"], [
        "ablation",
        "excluded_total_keys",
        "excluded_mock_keys",
        "excluded_test_keys",
        "excluded_out_of_scope_keys",
        "excluded_other_keys",
        "excluded_unlabeled_keys",
        "excluded_nonlabel_rows_raw",
    ])
    _write_csv(out_dir / "master_conflicts.csv", tables["master_conflicts"], [
        "ablation",
        "finding_key",
        "sheet",
        "finding_header",
        "finding_kind",
        "scored_labels",
        "resolved_label",
        "row_count",
        "row_indices",
        "type_values",
    ])
    _write_csv(out_dir / "master_union_coverage.csv", tables["master_union_coverage"], [
        "ablation",
        "positive_keys",
        "union_positive_keys",
        "coverage_vs_union_positive"
    ])
    _write_csv(out_dir / "runtime_summary.csv", runtime_rows, [
        "ablation_id",
        "ablation_name",
        "config_name",
        "repos_total",
        "repos_nonempty",
        "contracts_total",
        "wallclock_sum_s",
        "mean_repo_s",
        "median_repo_s",
        "sec_per_contract",
    ])
    print(f"Wrote 7 CSV outputs to {out_dir}")

if __name__ == "__main__": main()