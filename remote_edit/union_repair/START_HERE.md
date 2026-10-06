# Human Review: Start Here

Use only the sheet assigned to you and the packet named in each row. Do not
inspect `freeze/`, detector configurations, another reviewer's sheet, or
administrative selection files.

| Assignment | Sheet | Guide |
| --- | --- | --- |
| Web3Bugs primary | `web3bugs_primary.csv` | `WEB3BUGS_GUIDE.md` |
| Web3Bugs agreement | `web3bugs_agreement.csv` | `WEB3BUGS_GUIDE.md` |
| ISU reviewer 1 | `isu_reviewer_1.csv` | `ISU_GUIDE.md` |
| ISU reviewer 2 | `isu_reviewer_2.csv` | `ISU_GUIDE.md` |

For each row, open the JSON path in `packet` or `evidence_packet`, complete all
required fields, and add a short evidence note. The agreement reviewer and the
two ISU reviewers work independently.

ISU reviewers classify only the published finding shown in the packet; they do
not inspect detector output. After ISU adjudication, the research team runs
`runners/prepare_isu_strict_match.py` to create the separate B0 matching task
for findings adjudicated as `MV_SI`.

If the supplied evidence cannot support a decision, use
`INSUFFICIENT_EVIDENCE` and state exactly what is missing. Do not search the
administrative tree for additional clues.
