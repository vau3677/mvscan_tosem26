# Evaluation Storage Audit

Date: 2026-08-18  
Scope: frozen ISU/Web3Bugs evaluation workspace and paused F2 execution  
Semantic detector output inspected: no

## Executive conclusion

The host is not under CPU, memory, swap, inode, or I/O pressure. The `/home` filesystem is the limiting resource: it is 96% full with approximately 125 GiB free. Leaving detector JSON uncompressed would be unsafe because the current 160 terminal attempts already contain 18.07 GB of raw and canonical JSON.

The detector output is extraordinarily compressible. A complete Zstandard level-1 measurement of every current raw and canonical output reduced 18,072,121,797 bytes to 134,166,853 bytes (0.742%). The storage problem is representation, not irreducible research evidence.

## Current footprint

| Category | Disk bytes | Approximate size |
| --- | ---: | ---: |
| Entire project | — | 171 GiB (`du`) |
| Benchmarks | 140,582,006,784 | 131 GiB |
| Canonical runs | 18,230,882,304 | 17.0 GiB |
| Quarantined attempts | 13,340,151,808 | 12.4 GiB |
| Frozen environment | 6,279,688,192 | 5.8 GiB |

The project-total display above is reported by `du` as 171 GiB; component byte counts are the authoritative audit measurements.

## Canonical output composition

| Category | Apparent bytes |
| --- | ---: |
| Raw detector JSON | 11,501,491,856 |
| Canonical detector JSON | 6,570,629,941 |
| Bundled detector/runner copies | 117,071,872 |
| Manifests and metadata | 28,731,645 |
| Logs | 8,818,024 |
| Other root files | 822,560 |

Ordinary logs account for less than 0.05% of canonical-run storage. Deleting logs would not materially help.

## Output distribution

| Statistic | Raw JSON | Canonical JSON |
| --- | ---: | ---: |
| Median | 684,566 B | 439,378 B |
| P90 | 33,050,594 B | 16,477,311 B |
| P95 | 642,808,271 B | 363,960,733 B |
| Maximum | 2,013,154,569 B | 1,180,645,459 B |

The distribution is extremely heavy-tailed. The largest raw output contains 1,479 candidates, 186,777 serialized context instances, 444,748 serialized reader witnesses, and 1,789,626 `entity_key` occurrences. The volume is exhaustive repeated evidence serialization rather than ordinary logging.

## Exact lossless compression result

| Artifact class | Source bytes | Zstd-1 bytes | Retained fraction |
| --- | ---: | ---: | ---: |
| Raw JSON, all current attempts | 11,501,491,856 | 78,093,196 | 0.679% |
| Canonical JSON, all current attempts | 6,570,629,941 | 56,073,657 | 0.853% |
| **Combined** | **18,072,121,797** | **134,166,853** | **0.742%** |

The largest raw file compressed from 2.013 GB to 12.65 MB in 0.626 seconds. The largest canonical file compressed from 1.181 GB to 9.46 MB in 0.386 seconds.

At the current average, an uncompressed 918-entry maximum plan projects to roughly 104 GB of semantic JSON. Applying the measured aggregate compression ratio projects that same JSON to roughly 0.77 GB. This is an estimate because later subjects may have a different size distribution.

## Build-attempt storage

| Dataset/class | Attempts | Disk bytes |
| --- | ---: | ---: |
| ISU accepted | 88 | 20,649,623,552 |
| ISU nonaccepted | 133 | 23,724,802,048 |
| Web3Bugs accepted | 65 | 27,049,725,952 |
| Web3Bugs nonaccepted | 161 | 64,398,286,848 |

Nonaccepted build attempts occupy 88,123,088,896 bytes. None is referenced by the 153 execution-subject manifests.

Largest nonaccepted components include:

| Component | Disk bytes |
| --- | ---: |
| Expanded dependency archives | 36,495,540,224 |
| Workspaces | 24,348,786,688 |
| Yarn caches | 21,435,879,424 |
| npm caches | 4,115,513,344 |

The small attempt manifests, original-file inventories, and stdout/stderr logs provide the exclusion evidence. The repeated caches and workspaces are not needed by the active execution runner.

## Machine health at audit

| Resource | Observation |
| --- | --- |
| `/home` | 2.6 TiB total, 96% used, approximately 125 GiB free |
| `/tmp` | approximately 383 GiB free on a separate filesystem |
| Inodes | 19% used on `/home` |
| Memory | 503 GiB total, approximately 492 GiB available |
| Swap | 9 MiB used of 8 GiB |
| Load average | 1.03 / 0.59 / 0.30 |
| Active evaluation | paused; no child is writing |

## Protocol-safe recommendation

1. Preserve both raw and canonical logical artifacts, as required by F2, but store them as `.json.zst` after validation.
2. Record both the original uncompressed SHA-256 and compressed-file SHA-256, byte sizes, compression algorithm, and level in each run manifest.
3. Verify decompression reproduces the original SHA-256 before removing an uncompressed file.
4. Update validators and later analysis tools to stream-decompress transparently.
5. Amend and reseal the storage representation before resuming; detector semantics and JSON content remain unchanged.
6. Separately relocate or prune nonaccepted workspaces and package-manager caches while retaining attempt manifests, original-file inventories, logs, and deviation records.
7. Keep the launcher paused until the storage representation is approved and verified on existing attempts.

No canonical or quarantined artifact was moved, compressed in place, or deleted during this audit. Compression probes wrote only temporary files under `/tmp` and removed them automatically.
