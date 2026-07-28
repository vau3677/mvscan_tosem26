# README.md - MV-Scan Research Artifacts

This repository contains the source code for the **MV-Scan** tool, the analysis rules used in the experiment, the dataset of target repositories, and the Python scripts used to orchestrate and evaluate the experiment.

## Repository Structure

1. **Ablation study and basic evaluation**. This evaluation is done over 61 Web3Bugs repos, each repo with 5 distinct ablations and the reference configuration (a total of 6 runs each). We report precision, triage-yield, runtimes, and compare the results to determine how components independently contribute to the reference configuration's performance.

2. **Oracle.** The independent annotation pass over 116 known-bug rows from a previous TOSEM study that labeled and identified ISU vulnerabilities from various repositories. These are confirmed as ISU, so it is our job to build on the literature by semantically distinguishing MV-SI from SV-SI from ISU-other. Once this is done, we then compare them to our reference configuration's performance. We also do a separate annotation pass over the zero-days we discovered during our evaluation/ablation study (over 61 repos). We report agreement and Cohen's kappa with reported disagreements and adjudications over both the known-bugs (MV-SI denominator) and the zero-days. We then use that data to report strict lower-bound recall.

```
oracle
  TOSEM_study_folder/    # the original ISU study artifacts
  download_ISU_study.py  # downloads the TOSEM ISU study artifacts used in our oracle
  generate_packet.py     # generate the packet we use to annotate semantic MV-SI
  packet/                # the packet handed to each annotator; includes the known-bug rows to be labeled and compared to B0 with our orthogonal criteria
    known_bug_rows.csv   # the 116 rows with our additional columns/schema
    zero_day_rows.csv    # the rows from our evaluation of 61 Web3Bugs repositories
  reports/
    A1/                        # annotations from annotator 1 (will include a packet/)
    A2/                        # annotations from annotator 2 (will include a packet/)
    known_bug_rows_results.csv # final semantic labels (MV-SI/SV-SI/ISU-other) with reference configuration matches
    zero_day_rows_results.csv  # final agreements on zero-days with accompanying PoCs, traces, and notes
    oracle_results.csv         # all final oracle numbers including strict lower-bound recall
    generate_results.py        # generates the final known-bug results and zero-day results, with all reported numbers in oracle_results.csv

evaluation
  master.py              # generates the results from our ablation_study.csv
  <results go here>

slither-si-detector/     # source code for the MV-Scan tool that is located at /slither/detectors/inconsistent_state
```

## MV-Scan Tool

Our custom analysis tool uses Slither/SlitherIR to interface with smart contract code. Slither is a Solidity & Vyper static analysis framework written in Python3. It runs a suite of vulnerability detectors, prints visual information about contract details, and provides an API to write custom analyses.

### Building & Running

From source:

```bash
# First install Slither and configure it to run as required
cd slither-si-detector
python3.10 -m pip install -e .

# Smoke test: can you run `slither`?

# Locate your target Solidity repository and compile it
npx hardhat clean && npx hardhat compile

# Run the inconsistent_state detector over your repository
ISD_JSON_OUT=out.json slither smart-contract/repo --detect inconsistent_state
```

The instructions above install MV-Scan as a Slither plugin and pins the frontend to `slither-analyzer==0.11.3`. The detector is discovered through Slither's standard plugin entry point.