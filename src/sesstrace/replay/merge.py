"""Put the results of several attempts of one series into one folder.

A series is sometimes finished in more than one attempt. When the image of
one release cannot be fetched, that release is run again on its own, and each
attempt leaves a results folder that holds only its own runs. Evaluated alone,
either folder reports the runs of the other as missing. The folders are
therefore copied, unchanged, into one new folder, which is then evaluated and
audited like any other.

Nothing is overwritten. A file that two attempts both hold means that
something was run twice, and the merge stops there: which of two runs counts
is not a decision for a copy step. A cell that is attempted again on purpose
is a new series with its own specification; `evaluate.combine` puts such
series into one table.
"""
import shutil
from pathlib import Path

from ..fileio import sha256_file


class Overlap(Exception):
    """Two attempts hold a file of the same name."""


def labels(sources):
    """Name every attempt by the last two parts of its path, for example `first_attempt/results`.

    The record of a merge then does not carry where the folders lay on the machine. When two attempts would get
    the same name, the paths are recorded as they were given.
    """
    short = ["/".join(Path(source).parts[-2:]) for source in sources]
    return short if len(set(short)) == len(short) else [str(source) for source in sources]


def merge(sources, out_dir):
    """Copy the files of every results folder into `out_dir`/results.

    Returns the record of the merge: for every attempt, in the order given,
    its name (see `labels`) and the files taken from it with their SHA-256.
    Raises Overlap before anything is copied when a file is in two attempts.
    """
    target = Path(out_dir) / "results"
    if target.exists():
        raise ValueError("the output folder already holds results: %s" % target)
    attempts = []
    owner = {}
    for source, label in zip(sources, labels(sources)):
        folder = Path(source)
        if not folder.is_dir():
            raise ValueError("not a folder: %s" % source)
        names = sorted(path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file())
        for name in names:
            if name in owner:
                raise Overlap("%s is in %s and in %s" % (name, owner[name], label))
            owner[name] = label
        attempts.append((label, folder, names))
    record = {"attempts": [], "files": len(owner)}
    for label, folder, names in attempts:
        rows = []
        for name in names:
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(folder / name), str(destination))
            rows.append({"file": name, "sha256": sha256_file(destination)})
        record["attempts"].append({"results": label, "files": rows})
    return record
