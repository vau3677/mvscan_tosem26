# TOSEM-aligned section contract

This is a program-analysis technique and software-contribution paper. MV-Scan's
static analysis is the primary contribution; the implementation realizes that
technique; and the empirical study evaluates both. The datasets and annotation
process are evaluation evidence, not the paper's identity.

TOSEM's public author guidelines do not mandate a fixed sequence of section
titles. They define the qualities and evidence a publishable paper must
provide. This directory maps each requirement to exactly one primary location
so that no requirement is lost and no competing outline is created.

| TOSEM expectation | Primary manuscript location |
| --- | --- |
| Important software-engineering problem and practical relevance | `01-introduction.tex`; `02-background-and-motivation.tex` |
| Clear statement of what is new and significant | `01-introduction.tex`; `04-approach.tex` |
| Technical precision and soundness | `03-problem-definition.tex`; `04-approach.tex` |
| Reproducible and extensible analysis/software | `04-approach.tex`; `05-implementation.tex`; `a-artifact-and-reproducibility.tex` |
| Clearly described experimental method | `06-evaluation-methodology.tex` |
| Scalability evidence | `07-results.tex`, Section 7.4 |
| Interpretation in terms of software-engineering practice | `08-discussion.tex` |
| Every claim substantiated through detailed argument | Introduction contribution map; Sections 6--9 |
| Explicit limitations and validity risks | `09-threats-to-validity.tex` |
| Comparison with related work | `10-related-work.tex` |
| Concise statement of demonstrated contribution | `00-abstract.tex`; `11-conclusion.tex` |

## Section responsibilities

1. **Introduction** establishes the problem, gap, insight, evidence-backed
   contributions, and scope. Every contribution must point to later evidence.
2. **Background and Motivating Example** establishes practical relevance with
   one complete example and only the background needed to understand it.
3. **Multi-Variable State Inconsistencies** defines the target construct and
   separates it from exploitability, novelty, severity, and detector output.
4. **MV-Scan** is the technical center of the paper. It explains relation
   discovery, transition analysis, consumer/sink analysis, candidate
   construction, complexity, and deliberate overapproximations. It describes
   the frozen evaluated detector, not proposed future improvements.
5. **Implementation** explains the software architecture and how it realizes
   the analysis, emphasizing technical decisions rather than a feature list.
6. **Evaluation Design** evaluates the technique and software. It states RQs,
   populations, units, screening, annotation,
   adjudication, sampling, configurations, measures, and statistics before any
   result is interpreted.
7. **Results** answers each RQ with a direct answer, raw counts and denominators,
   a table, and a restrained interpretation.
8. **Discussion and Practical Implications** explains what the results mean for
   static-analysis researchers and reviewers, then distinguishes supported
   conclusions from future-work hypotheses.
9. **Limitations and Threats to Validity** covers construct, internal,
   conclusion, and external validity without claiming that mitigations erase
   the threats.
10. **Related Work** compares technical capabilities and empirical units rather
    than listing papers chronologically.
11. **Conclusion** restates only what the evaluation demonstrated.

The abstract and artifact appendix support this sequence but do not replace
essential arguments in the main paper. TOSEM currently states that appendices
longer than one page are published online-only, so reviewers must not need an
extended appendix to understand or verify a central claim.
