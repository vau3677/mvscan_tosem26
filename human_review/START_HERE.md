# Start here

Use only the sheet assigned to you and the packet named in each row.

| Assignment | Sheet | Guide |
| --- | --- | --- |
| Web3Bugs primary | `web3bugs_primary.csv` | `WEB3BUGS_GUIDE.md` |
| Web3Bugs agreement | `web3bugs_agreement.csv` | `WEB3BUGS_GUIDE.md` |
| ISU reviewer 1 | `isu_reviewer_1.csv` | `ISU_GUIDE.md` |
| ISU reviewer 2 | `isu_reviewer_2.csv` | `ISU_GUIDE.md` |

For Web3Bugs, follow `WEB3BUGS_GUIDE.md`. For ISU, read `ISU_GUIDE.md`, then review `known_findings/README.md` in order. Leave C1-C5 blank when they pass, enter `N` only for a failed criterion, or `U` when the evidence cannot establish a criterion. Add one short note only when using `N` or `U`, and set `review_complete` to `Y` after checking all five criteria. The final ISU class is derived automatically; reviewers do not enter a separate verdict. The agreement reviewer and the two ISU reviewers work independently.

ISU reviewers classify only the published finding shown in the packet. After ISU adjudication, the research team runs `runners/prepare_isu_strict_match.py` to create the separate B0 matching task for findings adjudicated as `MV_SI`.

If the supplied evidence cannot support a decision, enter `U` and state exactly what is missing. Do not search the administrative tree for additional clues.
