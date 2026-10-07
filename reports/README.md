# Historical administrative reports

The old setup inventories, setup/readiness reports, earlier audit snapshots, and superseded pre-verification compilation report are ignored in the default checkout. Their original files remain on the preparation machine and in preserved Git commit `3e9b63c37a4558a2e31560593ce768d9c5d1a867`.

Restore their exact paths and verify hashes from the repository root:

```bash
python3.10 publication/restore.py historical --download
```

This restores all ignored historical material, including historical setup reports under `reports/audit_attempts/`. It refuses to overwrite locally changed files.

Hidden administrative records:

- `SUBJECT_MANIFEST_DISCOVERY*.json` (seven generated status summaries; the 153 execution subject manifests remain tracked)

- `ARTIFACT_INVENTORY.csv`
- `FINAL_SETUP_REPORT.md`
- `F1_READINESS.md`
- `audit_attempts/001-before-final-readiness-refresh/ARTIFACT_INVENTORY.csv`
- `audit_attempts/001-before-final-readiness-refresh/FINAL_SETUP_REPORT.md`
- `audit_attempts/002-before-completion-audit-corrections/ARTIFACT_INVENTORY.csv`
- `audit_attempts/002-before-completion-audit-corrections/FINAL_SETUP_REPORT.md`
- `superseded/COMPILATION_FREEZE.preverification.md`

The pre-verification report is at the last path above; the historical `COMPILATION_FREEZE.md` text refers to an older `freeze/superseded/` location.

`benchmarks/isu/source_resolution.v2.csv` is also ignored because it is byte-identical to the retained historical `source_resolution.v1.csv`. The authoritative `benchmarks/isu/source_resolution.csv` remains tracked and differs from these older versions.

The retained compilation reports and cohort/exclusion records remain accessible in this directory. Scientific detector outputs, annotations, manifests, and manuscript files are unchanged.
