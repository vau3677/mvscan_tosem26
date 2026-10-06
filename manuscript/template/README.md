# TOSEM manuscript template

This directory contains the production release of ACM's `acmart` LaTeX
package downloaded from CTAN on 2026-08-28.

- Package: `acmart`
- Version: 2.20
- Class release date: 2026-08-16
- Upstream archive: <https://mirrors.ctan.org/macros/latex/contrib/acmart.zip>
- Package page: <https://ctan.org/pkg/acmart>
- SHA-256: `93933ce58fbeffa13e23398bb523fcb68275ecc73369c6bc73b421eeef2c10de`

The untouched downloaded archive is
`acmart-2.20-2026-08-16.zip`. The `acmart/` directory is its extracted
contents. `acmart.cls` and the sample `.tex` files were generated from the
included documented sources using the supplied `.ins` files.

TOSEM is an ACM journal. Use `acmart/samples/acmsmall.tex` as the journal
layout reference. For the manuscript sent for review, ACM's current general
submission instructions require single-column manuscript mode:

```tex
\documentclass[manuscript,screen,review]{acmart}
```

Add `anonymous` only if the TOSEM submission system or editor explicitly
requires an anonymized review copy. Production metadata and the final
publication format should be changed only when ACM supplies the acceptance
and TAPS instructions.

Note: the upstream `README` says `Version 2.20 2028-08-16`, which appears to
be a typographical error. The authoritative class declaration in
`acmart.dtx` says `2026/08/16 v2.20`, matching CTAN's package record.
