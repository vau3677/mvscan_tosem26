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

The draft starts in ACM single-column review mode. Internal comments are
enabled in `main.tex`:

```tex
\VU{discussion for Vladislav}
\YL{discussion for Yinxi}
\VUTODO{action for Vladislav}
\YLTODO{action for Yinxi}
```

Set `\internalcommentsfalse` before sharing a clean manuscript. A clean build
must contain no visible VU/YL comments, placeholder email addresses, TODOs,
undefined references, or invented ACM production metadata.

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

- Confirm title, author order, affiliations, emails, and every author's ORCID.
- Generate and insert accurate ACM CCS concepts and XML.
- Confirm whether the current editorial process requests an anonymous copy;
  the public TOSEM guidelines do not currently state that it does.
- Remove internal comments and TODOs and audit all manuscript numbers against
  machine-readable artifacts.
- Check that essential content is in the paper; appendices over one page are
  online-only under TOSEM's current policy.
- Prepare a short supplemental-material README with contents, requirements,
  expected runtime, and table-reproduction mapping.
- After acceptance, follow the production instructions supplied by ACM rather
  than guessing DOI, rights, volume, issue, or final layout metadata.
