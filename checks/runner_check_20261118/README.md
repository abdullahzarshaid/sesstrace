# Check of the changed runners, 18 November 2026

The release test of 17 November found seven defects and gaps (`../release_test_20261117/README.md`). The runners and the
package were changed for each of them (version 3.1.0). This check ran those changes on a container engine, at commit
`82c7ef6`. Every step came out as expected and no runner script had to be repaired.

## Where and when

The same Linux machine as the release test (Kali GNU/Linux 2026.1, kernel 6.19.11, Docker 28.5.2, host Python 3.13.12),
17 November 2026, 20:48 to 21:07 UTC, which is 18 November local time. `environment.txt` has the times of every step.

## Steps and results

| Step | What it exercises | Result |
|---|---|---|
| Unit tests on the host | The whole suite; five tests run shell functions of `common.sh` against a stand-in engine | 137 tests, OK, none skipped |
| Line witness | The audit of the witness runs; the pull record per target | 4 of 4 witnessed, counts 1, 1, 4, 1; audit: 8 runs, 64 requests, no problem |
| Third application series in two halves | `ONLY_REVISION`, `merge.sh`, the log head of every run, the third series | Each half alone: no valid run for the cell, 3 runs without records. Both together: the published verdict, category and counts (as specified, accepted 3 of 3 before the repair, refused 3 of 3 after it); audit: 6 runs, 60 requests, no problem |
| Merge of the same attempt twice | The refusal of a file that is in two attempts | Stopped with `nothing was copied`, status 1, no results folder |
| Every pull refused, images on the machine | `fetch_image` for the tool image and both releases | Both releases started; all three pull records end with the line that the image on the machine is used |
| Every pull refused, application images removed | The same, without a local image | Both releases reported as not pulled; the engine recorded no container event |
| Build of the distribution images | The build record | Ten lines with `build_exit=0 steps_from_cache=1`; no empty `results` folder |

The halves of the third series were run on purpose, to exercise the merge. Each release was run once and nothing was run
twice.

The build took 50 seconds, because every build step came from the cache of the engine, although the derived images had
been removed after the release test. An independent build therefore needs `REBUILD=1`.

## Checking it from this folder

```bash
sesstrace compare --counts checks/records/application_cells_third/evaluation.json checks/runner_check_20261118/evaluations/third_merged.json
python -m unittest tests.test_runner_check
```

## What the check noted, and what was changed afterwards (version 3.1.1)

| No. | Noted | Change |
|---|---|---|
| 1 | A runner that skipped every release still ended with status 0. | `applications.sh` ends with status 3 when a release was skipped because its image could not be fetched. What could be run is still run and evaluated. |
| 2 | `merge.sh` evaluated with the specification as it lay in the repository, without checking it against the freeze block. | `merge.sh` checks the block `applications_<series>` first and stops when a frozen file has changed. |
| 3 | `steps_from_cache=1` did not say of how many. | The build record reads `steps_from_cache=1 of 1`. |
| 4 | The build cache outlives the removal of the derived images. | Stated in the header of `distributions.sh` and in `../README.md`. |
| 5 | The merge record named the attempts by absolute paths of the machine. | `sesstrace merge` names an attempt by its folder, for example `first_attempt/results`. |

One suggestion was not taken up: an audit of half a series lists every missing run of the other half, where one line per
release would do. The audit output stays as it is.

These five changes were made after the check. The change to the package (item 5) is covered by unit tests. The three
changed runner scripts were then exercised against a stand-in for the container engine with
`bash tools/dry_run_runners.sh <empty folder>`; the output of that run is `dry_run_of_the_later_changes.txt`. A stand-in
shows what the scripts decide on the host. It is not a run on a container engine, and these three changes have not had
one.

## Files

| File | Content |
|---|---|
| `environment.txt`, `host_unit_tests.txt` | The machine, the times of every step, the unit tests on the host |
| `FREEZE_LOG.txt` | The two freeze blocks of this check, each committed before its step started (commits `70e914c` and `1f07479`) |
| `evaluations/`, `audits/` | The witness series and the third application series: each half alone and both together |
| `pulls_refused/` | The three pull records of the run with the images on the machine, and the host record of the run without them |
| `distributions_build_records.txt` | The build record |
| `dry_run_of_the_later_changes.txt` | Output of `tools/dry_run_runners.sh` at version 3.1.1 |
| `SHA256SUMS.txt` | Digests of the copied result files |

The raw records of this check (323 files) are kept by the authors and are not part of the repository.
