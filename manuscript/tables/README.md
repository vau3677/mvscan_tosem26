# Table conventions

The authoritative values remain in `../../results/final/`. These files are
paper renderings, not a second source of evaluation truth. Whenever a number
changes after an audit, update the machine-readable result first and then
rematerialize the corresponding LaTeX table.

Rules for every table:

- Put `\caption` before `\label`, and both above the table body.
- Use `booktabs`; never use vertical rules or repeated horizontal grid lines.
- Include raw numerators and denominators beside percentages.
- Name the evaluation unit explicitly: finding, native candidate, structural
  bucket, audited bucket, or consolidated finding.
- Use a leading zero for decimals and consistent precision within a column.
- State confidence-interval type and level in the caption, note, or prose.
- Use `--`/`---` only for not applicable; explain missing or skipped data.
- Do not shrink text below `\small`. Split or redesign an overcrowded table.
- Every table must be cited in prose before it appears.
- Add a meaningful `\Description{...}` for ACM accessibility. Do not merely
  repeat the caption; describe what a reader should learn from the structure.
- Keep captions self-contained and distinguish primary from exploratory data.
- Never present the 301 TP buckets as 301 distinct or novel vulnerabilities.
