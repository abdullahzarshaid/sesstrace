# Changelog

## 3.1.0 (unreleased)

Changes after the release test of 17 November 2026 (`checks/release_test_20261117/README.md`), and the records of one
further series.

Added
- `sesstrace merge`: puts the results of several attempts of one series into one folder and stops when a file is in two
  of them; `checks/run/merge.sh` runs it with the evaluation and the audit.
- `sesstrace witness audit`: checks the witness runs against the plans of their cells. The witness runner writes it.
- `sesstrace compare --counts`: the counts of valid replays of every cell must agree as well.
- Third application series: the further attempt of T5.grant_withdrawn of 17 November 2026 (`checks/phase3c/`, records in
  `checks/records/application_cells_third/`, `applications.sh third`). The cell is confirmed; 23 cells, 22 as specified.
- `checks/release_test_20261117/`: the evaluations of a fresh run of every series with version 3.0.0, and tests that
  compare them with the published records.

Changed
- `sesstrace run` ends with status 1 when a step ended in an error; the records are written as before.
- Runners: an image pinned by digest that is already on the machine is used when the registry cannot be reached; the
  application log head is saved for every run; the distribution build record states the steps that came from the cache
  and `REBUILD=1` builds without it; the application runner removes the container, volume and network of a run when it
  is stopped in the middle of one; only the runners that write results create `results/`.
- 137 tests (112 before).

## 3.0.0 (17 November 2026)

The state that passed the release test of 17 November 2026 (commit `9792762`).

The laboratory and the replay harness become one package with a command line.

Added
- `sesstrace.replay`: specification checker, freeze log, driver, evaluator, audit and line witness as modules, with the
  commands `spec`, `freeze`, `run`, `evaluate`, `audit`, `witness` and `report`.
- `sesstrace audit`: checks every recorded run against its plan using the traces, and every summary against its trace.
- `sesstrace report`: one table from several evaluations; a cell attempted twice is taken from the later series.
- `sesstrace lab verify`: runs the laboratory and compares it with the reference output kept in the package.
- `checks/`: the frozen specifications, host applications, adapters and set-up scripts of the eight public targets, the
  records of the published runs, and container runners that use the package.
- `sesstrace compare`: the verdicts and categories of a fresh evaluation against a reference one.
- A test suite of 112 tests: the 36 tests of the laboratory, stub-server tests of the driver and the evaluator, tamper
  tests of the audit, and tests that reproduce the archived evaluations from the archived records.

Changed
- The laboratory lives in `sesstrace.lab`; the expiration fixtures M7 and M8 are the module `sesstrace.lab.expiry`.
- The typed outcome and the replay verdict moved to `sesstrace.outcome`, shared by the laboratory and the replay engine.
- Output files are written with LF line endings on every system.
- Python 3.7 or later (the laboratory alone needed 3.10).

Unchanged on purpose
- The trace recorder, the four laboratory servers and the mechanisms M1 to M6: a fresh run writes the twelve archived
  trace files byte for byte.
- The summary and evaluation formats: the evaluator writes the archived evaluation files byte for byte from the archived
  records.

## 2.0.0

The synthetic laboratory as archived with the manuscript: mechanisms M1 to M6 with typed outcomes, contract-specific
denials and three controls per scenario, and the expiration fixtures M7 and M8.

The checks on public software of 14 and 15 November 2026 were run with this release and with driver and evaluator
scripts frozen per series; those scripts are in the supplementary material of the manuscript.
