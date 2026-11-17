# Release test of 17 November 2026

Every series of the checks was run again from this repository, at commit `95f36f8` (package 3.0.0), with the runners in
`checks/run/`. Those runners had not been run before; the published records in `checks/records/` were made with the scripts
that were frozen for each series at the time. The test had two questions: do the runners work, and does a fresh run give
the published results.

Both answers are yes. No runner script had to be repaired for a series to run. Seven defects and gaps were found on the
way; they are listed at the end with what was changed for each.

## Where and when

One Linux machine (Kali GNU/Linux 2026.1, kernel 6.19.11, Docker 28.5.2, host Python 3.13.12), 17 November 2026, 16:40 to
19:28 UTC. Third-party software ran only in throw-away containers. `environment.txt` has the details and the times of
every series.

## Results

| Series | Fresh result | Same as published |
|---|---|---|
| Unit tests on the host | 112 tests, OK | |
| Laboratory on 15 images | 15 of 15 identical: 112 tests and 12 of 12 trace files in each | yes |
| Library cells | 8 cells; 160 runs, 1,360 requests, no problem in the audit | 8 of 8, with equal counts |
| Line witness | 4 of 4 witnessed; refusal counts 1, 1, 4, 1 | yes |
| Application cells | 14 cells; 84 runs, 792 requests, no problem in the audit | 14 of 14, with equal counts |
| Further application cells | 2 cells; 12 runs, 114 requests, no problem in the audit, 6 requests not sent | 2 of 2, with equal counts |

Together 256 runs and 2,266 requests, as in the published records of these series.

Three remarks.

- **Two images differ in one version number.** AlmaLinux 9 and Amazon Linux 2023 were built again and installed Python
  3.12.16, where the published records have 3.12.15. Their output is identical all the same. The other eight derived
  images came from the build cache of the machine (see item 5 below).
- **The application series needed two attempts.** In the first, the registry did not answer when the image of the fixed
  release of T8 was pulled (`applications_first_attempt_1_pull_T8_fixed.txt`), and the runner skipped that release: 72 of
  84 runs. The release was then run alone, 12 runs. No run was made twice. The results of both attempts were put into one
  folder, 151 and 25 files with none in both, and evaluated and audited as one; that evaluation is
  `evaluations/applications_first.json`. Each attempt alone is kept as well: the first gives 10 of 14 cells, because the
  four cells of T8 lack one release.
- **T5.grant_withdrawn came out as in its first attempt.** In the series run here the application answered a control with
  HTTP 429 in all six runs, as it had on 15 November, so the cell has no valid run. The further attempt of that cell, with
  the limit of the application raised, is a series of its own (`checks/phase3c/`, records in
  `checks/records/application_cells_third/`) and was not part of this test.

## Checking it from this folder

```bash
sesstrace compare --counts checks/records/library_cells/evaluation.json            checks/release_test_20261117/evaluations/libraries.json
sesstrace compare --counts checks/records/application_cells/evaluation.json        checks/release_test_20261117/evaluations/applications_first.json
sesstrace compare --counts checks/records/application_cells_second/evaluation.json checks/release_test_20261117/evaluations/applications_second.json
python -m unittest tests.test_release_test
```

The test module compares all five evaluations with the published ones, including the witness and the distribution table.

## What the test found, and what was changed afterwards (version 3.1.0)

| No. | Found | Change |
|---|---|---|
| 1 | A failed pull made the application runner skip a release although the image, pinned by the same digest, was already on the machine. The library and witness runners would have stopped in the same case. | `fetch_image` in `common.sh`: when the pull fails and an image with that digest is present, it is used, and the pull record says so. An image named by a tag is never taken from the machine. |
| 2 | Nothing put two attempts of one series together; each attempt alone is evaluated with runs missing. | `sesstrace merge` copies the results folders of the attempts into one and stops when a file is in two of them. `checks/run/merge.sh` runs it and then the evaluation and the audit. |
| 3 | The witness runner wrote no audit. | `sesstrace witness audit` checks the witness runs against the plans of their cells; `witness.sh` runs it. The distribution runner replays nothing and has nothing to audit, which its header now says. |
| 4 | The first lines of the application log were saved for run 1 of a cell only. | They are saved for every run, with the run number in the file name. |
| 5 | The distribution build reused layers of an earlier build on the same machine: 8 of the 10 derived images. | The build record states for every image how many build steps came from the cache; `REBUILD=1` builds every step again. |
| 6 | The distribution runner left an empty `results/` folder. | Only the runners that write results create it. |
| 7 | `sesstrace run` ended with status 0 even when a step had ended in an error, so the recorded status said nothing. | Status 1 when the summary lists an error. The evaluator and the audit saw such errors before and still do. |

Two further changes came from the same reading: `sesstrace compare --counts` also compares the counts of valid replays,
and the application runner removes the container, volume and network of a run when it is stopped in the middle of one.

The changes to the package are covered by the unit tests. The changed runner scripts were run on a container engine on
18 November 2026; see `../runner_check_20261118/README.md`.

## Files

| File | Content |
|---|---|
| `environment.txt`, `host_unit_tests.txt` | The machine, the times of every series, the unit tests on the host |
| `FREEZE_LOG.txt` | The five freeze blocks, each written and committed before its series started (commits `4e77f52` to `9792762`) |
| `evaluations/` | The evaluation of every series as the runners wrote it; for the first application series both attempts and the two together |
| `audits/` | The output of the audit of every cell series |
| `applications_first_merge_record.txt` | Which attempt gave how many files |
| `distributions_table.txt`, `distributions_build_records.txt` | The table of the 15 images and the record of their pulls and builds |
| `SHA256SUMS.txt` | Digests of the files above, except the freeze log, whose digests are its own content |

The raw records of the 256 runs of this test (2,346 files) are kept by the authors and are not part of the repository.
