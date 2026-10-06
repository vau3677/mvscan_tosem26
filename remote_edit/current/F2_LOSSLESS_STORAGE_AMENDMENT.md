# F2 Lossless Storage Amendment

Date: 2026-08-18

## Reason

The first 160 terminal F2 attempts produced 18,072,121,797 bytes of raw and
canonical JSON. Exact measurement showed that Zstandard level 1 retains only
0.742% of those bytes. Continuing with plaintext JSON would create avoidable
pressure on the shared `/home` filesystem.

## Amendment

The protocol requirement to preserve raw and canonical detector output refers
to their logical, decompressed byte sequences. Those sequences may be stored as
`detector.json.zst` and `detector.canonical.json.zst` using Zstandard level 1.
This amendment changes storage representation only. It does not change detector
code, configurations, subjects, seeds, validation rules, canonicalization, run
ordering, selection, or statistical analysis.

For every compressed artifact, the run manifest records:

- the uncompressed path identity and SHA-256 already used by F2;
- uncompressed byte size;
- compression algorithm and level;
- compressed byte size and SHA-256; and
- successful decompression/round-trip verification.

An uncompressed artifact may be removed only after the compressed stream passes
`zstd -t` and streaming decompression reproduces its original SHA-256 exactly.
Validators and downstream analysis must read the compressed representation
transparently. Semantic-output embargo permissions apply to compressed files in
the same manner as to plaintext files.

Existing terminal attempts are migrated by the same procedure. The migration
is restartable and must fail closed on a missing file or hash mismatch.

## Operational residue

Workspaces and package-manager caches belonging to nonaccepted compilation
attempts are not members of the frozen execution cohort. They may be removed
after confirming that no accepted subject manifest references them. Attempt
manifests, source inventories, stdout/stderr, exclusion classifications, and
deviation records remain preserved.
