# Preservation audit — 2026-10-05

No files were deleted. Only root and mvscan-smoke Finder metadata (.DS_Store) were moved. manifest.json records original paths, archive paths, byte counts, and SHA-256 hashes. Every archived file was verified after the move.

## Findings and retention decisions

- KEEP mvscan-smoke/mvscan_slither_plugin.egg-info/: tracked installation metadata is explicitly copied by remote_edit/runners/run_mvscan.py, remote_edit/current/run_mvscan.py, remote_edit/union_repair/runners/run_mvscan.py, and remote_edit/runners/prepare_subject_manifests.py. The earlier suggestion that this was unnecessary was incorrect for this artifact.
- KEEP all mvscan-smoke/results/: tests require baseline/ and classification/; compare_exact_witness_repair.py requires pre-exact-witness-repair/classification/. Remaining historical outputs and icfg.py.original have not been proven dispensable for provenance.
- KEEP all remote_edit runner versions and .reviewer_optimization/: one begin_f2.py pair is byte-identical, but different path contexts and snapshot provenance can matter. Other runner versions differ. No canonical replacement was established.
- KEEP remote_exact_solc.patch: compiler handling exists in runners, but patch provenance and external usage have not been ruled out.
- KEEP all reviewer cards, previous versions, interfaces, handoff directories, and ZIP packets: packaging redundancy does not establish scientific redundancy; labels, evidence, external distribution, and links require comparison.
- KEEP manuscript/ in full, including generated outputs, bibliography, tables, and build files.
- KEEP results/final/: manuscript/README.md explicitly identifies it as the authoritative evaluation values.
- KEEP protocol/MVSCAN_EVALUATION_PLAN.md: manuscript/README.md identifies it as authoritative.
- KEEP dataset/, oracle/, evaluation/, runners/, deliverables/, isu_annotator_2_packet/, protocol/, results/, ideas/, and all detector source, contracts, and tests.

## Limits and requirements for subsequent moves

This is a conservative initial audit, not a completed proof of dispensability for the remaining candidates. Text references cannot rule out dynamic paths, external consumers, historical checksum manifests, or human use. Before moving scientific material: map each paper claim/table to source data and generator; resolve canonical runner versions; compare candidate copies including labels and evidence; inspect checksum/provenance manifests; check all internal links and path-dependent imports; reproduce affected outputs and tests; record hashes and original paths; and verify the resulting archive and working tree. Archive does not itself prevent broken execution paths.

## Restore

For each manifest record, verify the archived SHA-256, create the original parent directory, and move the archived file to original_path. Refuse to overwrite any existing destination. Paths are relative to the repository root. Finder may recreate .DS_Store after this audit; retain any recreated file rather than overwrite it during restoration.
