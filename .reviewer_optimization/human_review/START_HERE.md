# Start here

You will be assigned one or more CSV files. Only work on the files assigned to you. Do not look at another reviewer's answers.

## If you are reviewing the 116 published ISU findings

Use:

- `ISU_GUIDE.md`
- `known_findings/README.md`
- Either `isu_reviewer_1.csv` or `isu_reviewer_2.csv`

Read the cards in order. For each finding, enter `Y`, `N`, or `U` in `is_mvsi`.

- `Y`: the bug depends on two or more pieces of stored state getting out of sync.
- `N`: it does not.
- `U`: the supplied evidence is not enough to tell.

Write a short note only for `N` or `U`. You do not need to check whether MV-Scan found the bug. That happens later.

## If you are reviewing MV-Scan findings from Web3Bugs

Use:

- `WEB3BUGS_GUIDE.md`
- Your assigned `web3bugs_primary.csv` or `web3bugs_agreement.csv`
- The JSON packet named in each row

Review C1 through C5. Leave a C-column blank when it passes and enter `N` when it fails. Add a short evidence note and set `review_complete` to `Y`.

Do not open `ADMIN_SELECTION.json` or inspect detector configurations. Do not compare answers with another reviewer before both reviews are finished.

## What happens after review

The research team compares the independent sheets, sends disagreements for adjudication, and then checks whether MV-Scan recovered the published ISU findings. Reviewers should not do those later steps while completing their initial sheets.
