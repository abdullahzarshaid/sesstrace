# Changelog

## 3.0.0 (unreleased)

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
