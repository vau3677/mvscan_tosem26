# MV-Scan TOSEM manuscript

`main.tex` is the only manuscript entry point. Each numbered source in
`sections/` owns one paper section; do not create parallel drafts of the same
section. The TOSEM requirement-to-section mapping is recorded in
`sections/README.md`. Tables live in `tables/`, while the authoritative evaluation values
remain in `../results/final/`.

Build from this directory with:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

The manuscript uses ACM single-column anonymous review mode. Author names, affiliations, contact details, and private author-comment commands are excluded from the review source and rendered PDF. Bibliographic attribution to published work remains intact.

## Writing contract

- Treat the paper as a program-analysis technique and software-contribution
  paper: technique first, implementation second, empirical evidence third.
- The frozen evaluation plan in `../protocol/MVSCAN_EVALUATION_PLAN.md` remains
  authoritative. This manuscript structure does not replace it.
- Define every evaluation unit before reporting it and keep denominators
  consistent within comparisons.
- Use “strict historical recovery,” not general recall, for the 13/62 result.
- Use “candidate-level precision” for the sampled structural-bucket results.
- Treat configuration comparisons as reviewer-effort tradeoffs; samples are
  not paired causal observations.
- A supported relation is not necessarily vulnerable. Candidate-level TPs are
  not automatically distinct findings or zero-days.
- Report typical scalability together with the runtime/memory tail and disclose
  seed mismatches rather than implying perfect reproducibility.
- Keep claims concise, technically precise, and directly substantiated, in line
  with TOSEM's author guidelines.

## Submission checklist

- Keep author names, affiliations, contact details, acknowledgments, and author-identifying PDF metadata out of the review copy.
- Generate and insert accurate ACM CCS concepts and XML.
- Audit the manuscript for private comments and TODOs and verify all numbers against
  machine-readable artifacts.
- Check that essential content is in the paper; appendices over one page are
  online-only under TOSEM's current policy.
- Prepare a short supplemental-material README with contents, requirements,
  expected runtime, and table-reproduction mapping.
- After acceptance, follow the production instructions supplied by ACM rather
  than guessing DOI, rights, volume, issue, or final layout metadata.
