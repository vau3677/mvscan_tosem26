#!/usr/bin/env python3
"""Resolve explicit repository/revision links from frozen ISU report evidence."""

from __future__ import annotations

import csv
import gzip
import hashlib
import html
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.error
import urllib.request

from runners.common import ROOT, canonical_bytes

POPULATION = ROOT / "benchmarks" / "isu" / "oracle_population.csv"
OUTPUT = ROOT / "benchmarks" / "isu" / "source_resolution.csv"
EVIDENCE = ROOT / "benchmarks" / "isu" / "source_resolution_evidence"
FIELDS = (
    "oracle_row_id", "report_identity", "report_url", "resolution_status",
    "source_repository", "vulnerable_revision", "source_reference",
    "affected_source_paths", "explicit_blob_links", "section_sha256",
    "resolution_note",
)
BLOB_RE = re.compile(
    r"https://github\.com/([^/]+)/([^/]+)/blob/([^/\"'<>?#]+)/([^\"'<>?#]+)(?:#[^\"'<> ]*)?"
)
ISSUE_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "MVScan-academic-build-reconstruction/1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def cached_report(base_url: str) -> bytes:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(base_url.encode("utf-8")).hexdigest()
    path = EVIDENCE / "reports" / f"{key}.html.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return gzip.decompress(path.read_bytes())
    body = fetch(base_url)
    path.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    time.sleep(0.2)
    return body


def resolve_github_ref(owner: str, repo: str, reference: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", reference):
        return reference.lower()
    cache = EVIDENCE / "github_refs" / owner / repo / f"{urllib.parse.quote(reference, safe='')}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.is_file():
        document = json.loads(cache.read_text(encoding="utf-8"))
    else:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{urllib.parse.quote(reference, safe='')}"
        try:
            document = json.loads(fetch(url).decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            error_path = cache.with_suffix(".error.json")
            error_path.write_bytes(canonical_bytes({
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
            }))
            return ""
        cache.write_bytes(canonical_bytes(document))
        time.sleep(0.2)
    revision = str(document.get("sha", ""))
    return revision.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", revision) else ""


def primary_issue_body(section: str) -> tuple[str, str]:
    match = ISSUE_RE.search(html.unescape(section))
    if not match:
        return "", ""
    owner, repo, number = match.groups()
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}"
    cache = EVIDENCE / "issues" / owner / repo / f"{number}.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    try:
        if cache.is_file():
            document = json.loads(cache.read_text(encoding="utf-8"))
        else:
            document = json.loads(fetch(url).decode("utf-8"))
            cache.write_bytes(canonical_bytes(document))
            time.sleep(0.2)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return repo.removesuffix("-findings"), ""
    return repo.removesuffix("-findings"), str(document.get("body", ""))


def report_section(body: bytes, fragment: str) -> str:
    document = body.decode("utf-8", "replace")
    escaped_fragment = re.escape(html.escape(urllib.parse.unquote(fragment), quote=True))
    match = re.search(rf'<h[12][^>]+id=["\']{escaped_fragment}["\'][^>]*>', document, re.I)
    if not match:
        match = re.search(rf'<h[12][^>]+id=["\'][^"\']*{escaped_fragment}[^"\']*["\'][^>]*>', document, re.I)
    if not match:
        finding_prefix = re.match(r"h-?\d+", urllib.parse.unquote(fragment), re.I)
        if finding_prefix:
            escaped_prefix = re.escape(finding_prefix.group(0))
            match = re.search(
                rf'<h[12][^>]+id=["\']{escaped_prefix}(?:-[^"\']*)?["\'][^>]*>',
                document,
                re.I,
            )
    if not match:
        return ""
    next_heading = re.search(r"<h[12][^>]+id=", document[match.end():], re.I)
    end = match.end() + next_heading.start() if next_heading else len(document)
    return document[match.start():end]


def resolve_code4rena(row: dict[str, str]) -> dict[str, str]:
    split = urllib.parse.urlsplit(row["report_url"])
    base_url = urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, "", ""))
    body = cached_report(base_url)
    section = report_section(body, split.fragment)
    digest = hashlib.sha256(section.encode("utf-8")).hexdigest() if section else ""
    section_path = EVIDENCE / "sections" / f'{row["oracle_row_id"]}.html.gz'
    section_path.parent.mkdir(parents=True, exist_ok=True)
    if section and not section_path.exists():
        section_path.write_bytes(gzip.compress(section.encode("utf-8"), compresslevel=9, mtime=0))
    expected_repo, issue_body = primary_issue_body(section)
    links = []
    for owner, repo, revision, path in BLOB_RE.findall(html.unescape(section + "\n" + issue_body)):
        if repo.endswith("-findings"):
            continue
        links.append((owner, repo, revision.lower(), urllib.parse.unquote(path)))
    links = sorted(set(links))
    expected_links = [link for link in links if link[1] == expected_repo]
    if expected_links:
        links = expected_links
    identities = sorted(set((owner, repo, reference) for owner, repo, reference, _ in links))
    result = {
        "oracle_row_id": row["oracle_row_id"],
        "report_identity": row["report_identity"],
        "report_url": row["report_url"],
        "section_sha256": digest,
        "explicit_blob_links": json.dumps([
            f"https://github.com/{owner}/{repo}/blob/{reference}/{path}"
            for owner, repo, reference, path in links
        ], separators=(",", ":")),
        "affected_source_paths": json.dumps(sorted(set(path for *_, path in links)), separators=(",", ":")),
        "source_repository": "",
        "vulnerable_revision": "",
        "source_reference": "",
        "resolution_status": "UNRESOLVED_NO_EXPLICIT_BLOB_LINK",
        "resolution_note": "report section not found" if not section else "no exact source blob permalink in report section",
    }
    if len(identities) == 1:
        owner, repo, reference = identities[0]
        revision = resolve_github_ref(owner, repo, reference)
        result.update({
            "resolution_status": (
                "RESOLVED_EXPLICIT_REPORT_BLOB"
                if re.fullmatch(r"[0-9a-fA-F]{40}", reference)
                else "RESOLVED_EXPLICIT_REPORT_REF"
            ) if revision else "UNRESOLVED_EXPLICIT_REF_LOOKUP",
            "source_repository": f"https://github.com/{owner}/{repo}.git",
            "vulnerable_revision": revision,
            "source_reference": result["explicit_blob_links"],
            "resolution_note": (
                "exact repository and revision from report-section blob permalink"
                if re.fullmatch(r"[0-9a-fA-F]{40}", reference)
                else f"explicit report ref {reference} resolved to exact GitHub commit during acquisition"
            ),
        })
    elif len(identities) > 1:
        result["resolution_status"] = "UNRESOLVED_AMBIGUOUS_EXPLICIT_BLOBS"
        result["resolution_note"] = json.dumps(identities, separators=(",", ":"))
    return result


def main() -> int:
    rows = list(csv.DictReader(POPULATION.open(newline="", encoding="utf-8")))
    output = []
    for index, row in enumerate(rows, 1):
        host = urllib.parse.urlsplit(row["report_url"]).netloc.lower()
        if host == "code4rena.com":
            resolved = resolve_code4rena(row)
        else:
            resolved = {field: "" for field in FIELDS}
            resolved.update({
                "oracle_row_id": row["oracle_row_id"],
                "report_identity": row["report_identity"],
                "report_url": row["report_url"],
                "resolution_status": "UNRESOLVED_NON_CODE4RENA_REPORT",
                "resolution_note": "requires repository-specific report resolution",
            })
        output.append(resolved)
        print(json.dumps({"index": index, "oracle_row_id": row["oracle_row_id"], "status": resolved["resolution_status"]}), flush=True)
    for resolved in output:
        if resolved["resolution_status"] != "UNRESOLVED_AMBIGUOUS_EXPLICIT_BLOBS":
            continue
        try:
            identities = json.loads(resolved["resolution_note"])
        except json.JSONDecodeError:
            continue
        repositories = {(owner, repo) for owner, repo, _ in identities}
        exact = [(owner, repo, ref) for owner, repo, ref in identities if re.fullmatch(r"[0-9a-fA-F]{40}", ref)]
        if len(repositories) == 1 and len(exact) == 1:
            owner, repo, revision = exact[0]
            resolved.update({
                "resolution_status": "RESOLVED_EXPLICIT_REPORT_BLOB",
                "source_repository": f"https://github.com/{owner}/{repo}.git",
                "vulnerable_revision": revision.lower(),
                "source_reference": resolved["explicit_blob_links"],
                "resolution_note": "same repository was linked by branch and exact commit; selected the explicit exact commit",
            })
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(output)
    summary = {}
    for row in output:
        summary[row["resolution_status"]] = summary.get(row["resolution_status"], 0) + 1
    (EVIDENCE / "summary.json").write_bytes(canonical_bytes({"row_count": len(output), "status_counts": summary}))
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
