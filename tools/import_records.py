"""Copy the run records of the published checks into checks/records/.

Usage:  python tools/import_records.py <folder that holds the returned result folders>

Only the files the package reads are copied, unchanged: the set-up record of
every container, the summary and the trace of every run, the line counts of
the witness runs, the evaluation each series wrote at the time, and the
freeze logs. Logs, consoles, raw coverage and container records stay in the
archive. A list of SHA-256 values is written beside the copies.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sesstrace.fileio import sha256_file, write_text  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[1]
RECORDS = REPOSITORY / "checks" / "records"
FIRST = "results_20261114T232903Z"
SECOND = "results_phase2_20261115T010731Z"
THIRD = "results_phase3_20261115T095747Z"
FOURTH = "results_phase3b_20261115T141421Z"

# series name -> (results folder inside the archive, evaluation file inside the archive)
SERIES = {
    "libraries_single_run_1": (FIRST + "/external_targets/results", FIRST + "/external_targets/EXTERNAL_VERDICT.json"),
    "libraries_single_run_2": (SECOND + "/results", SECOND + "/PHASE2_VERDICT.json"),
    "library_cells": (THIRD + "/B_cells/run/results", THIRD + "/B_cells/CELL_RESULTS.json"),
    "application_cells": (THIRD + "/D_rest_of_list/merged_evaluation/results", THIRD + "/D_rest_of_list/CELL_RESULTS_D.json"),
    "application_cells_second": (FOURTH + "/run/results", FOURTH + "/CELL_RESULTS_3B.json"),
    "line_witness": (THIRD + "/C_line_witness/run/results", THIRD + "/C_line_witness/WITNESS_RESULT.json"),
}
# single files and folders copied as they are: (path inside the archive, path inside checks/records)
EXTRA = [
    (THIRD + "/C_line_witness/run/counts", "line_witness/counts"),
    (THIRD + "/A_distributions/MATRIX_RESULT.json", "distributions/evaluation.json"),
    ("external_targets/EXTERNAL_FREEZE.sha256", "freeze_logs/libraries_single_run_1.sha256"),
    (SECOND + "/phase2/FREEZE_LOG.txt", "freeze_logs/libraries_single_run_2.txt"),
    (THIRD + "/phase3/FREEZE_LOG.txt", "freeze_logs/cells_witness_distributions.txt"),
    (FOURTH + "/phase3b/FREEZE_LOG.txt", "freeze_logs/application_cells_second.txt"),
]
WANTED = ("setup_", "summary_", "trace_")


def copy(source, destination, copied):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(source), str(destination))
    copied.append(destination)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    archive = Path(sys.argv[1])
    if RECORDS.exists():
        shutil.rmtree(str(RECORDS))
    copied = []
    for name, (results, evaluation) in SERIES.items():
        source = archive / results
        for path in sorted(source.rglob("*")):
            if path.is_file() and path.name.startswith(WANTED):
                copy(path, RECORDS / name / "results" / path.relative_to(source), copied)
        copy(archive / evaluation, RECORDS / name / "evaluation.json", copied)
    for inside_archive, inside_records in EXTRA:
        source = archive / inside_archive
        if source.is_dir():
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    copy(path, RECORDS / inside_records / path.relative_to(source), copied)
        else:
            copy(source, RECORDS / inside_records, copied)
    lines = ["%s  %s" % (sha256_file(path), path.relative_to(RECORDS).as_posix()) for path in sorted(copied)]
    write_text(RECORDS / "SHA256SUMS.txt", "\n".join(lines) + "\n")
    print("%d files copied to %s" % (len(copied), RECORDS))


if __name__ == "__main__":
    main()
