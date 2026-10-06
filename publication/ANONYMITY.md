# Authorship anonymity audit

## Changed in the current publication tree

- Manuscript class uses anonymous review mode; author metadata contains only Anonymous Author(s).
- Study-author names, affiliations, contact fields, acknowledgments and author-specific private comment commands are removed from the manuscript source; the PDF is rebuilt and its text and metadata checked.
- Legitimate attribution in the bibliography and third-party code remains intact.
- The historical build helper resolves its project root from its own location rather than an investigator home directory.
- Investigator workspace prefixes in 1,918 metadata files (954 terminal manifests, 954 pending manifests, ten benchmark records) are replaced with `/workspace/artifact`. Original bytes are preserved in the pre-anonymization Git revision and a separate local backup. Only those path strings and the corresponding terminal-to-pending hash references change.
- `anonymization-map.json.gz` records original/redacted file hashes and sizes. The original evaluation snapshot remains unchanged; compare metadata through this mapping rather than claiming original byte identity.
- Bundle-download account names are not embedded in the tracked manifest. The restoration helper derives the configured origin's release location or uses `MVSCAN_BUNDLE_BASE_URL`.

## Material preserved unchanged

Detector source, raw and canonical detector outputs, annotations, sample selections, benchmark Solidity source and frozen release payloads retain their original scientific bytes. Table regeneration must reproduce all twelve result files byte-for-byte. Anonymizing author metadata is not a new detector evaluation.

## Remaining identity exposure

This GitHub-hosted artifact cannot be represented as a fully anonymous distribution:

1. The hosting account, previous commits, Git remotes, historical restoration revision and existing release attribution can identify the investigators. New commits use anonymous author/committer metadata, but existing history is preserved.
2. All three original TAR groups contain investigator account names in ownership headers: 98,838 accepted-input members, 36,006 source-evidence members, and 11,332 runtime-extension members. The total number of identifying headers is 146,176.
3. The accepted-input bundle has 259 content files containing identifying absolute build paths. Altering those files would change the frozen accepted-build hashes. They are not silently rewritten or discarded.
4. Restoring ignored historical material or original frozen inputs can reintroduce investigator identifiers into a local checkout.

The manuscript and sanitized metadata are prepared for anonymous authorship. Anonymous hosting/history and anonymized derivatives of original bundles require separate treatment before the *whole artifact* can be considered anonymous. No claim of full artifact anonymity is made.

## Verification coverage

The audit enumerated every tracked file, inspected all 1,783 compressed detector outputs, the compressed inventories, all Python-wheel members, manuscript PDF text/XMP metadata, and 146,178 release TAR members. The tracked compressed/PDF/wheel scan covered 63,770,283,405 expanded bytes; release TAR content scanning covered a further 6,750,625,599 bytes. Archive headers, links and ownership fields were checked separately. Git commit authorship and release/asset attribution were also inspected.

All 1,918 metadata transformations were checked against preserved originals. All twelve regenerated result files matched their pre-anonymization bytes. The three evaluated detector modules still match the frozen detector manifest. Remaining study-author-name matches in the current source/PDF are the legitimate bibliography entry for a cited published paper; they are not author-block or private-comment remnants.
