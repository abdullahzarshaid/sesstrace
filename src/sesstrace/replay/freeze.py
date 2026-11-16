"""Freeze blocks: a dated record of the files a check was run with.

Before a target receives its first request, the specification (with the
expected outcome of every checkpoint) and every script that will run are
hashed into a block of the freeze log. The runner checks the block again
before each run and stops when a file has changed. A later repair does not
edit a block; it adds a new block with the same name, and the last block with
a name is the one in force. The log therefore shows what was fixed when.

Format of FREEZE_LOG.txt

    === FREEZE <name> utc=<time>
    reason: <free text>
    <sha256>  <path relative to the folder of the log; may start with ../>
    ...
    === END
"""
import time
from pathlib import Path

from ..fileio import sha256_file

LOG_NAME = "FREEZE_LOG.txt"


class NoSuchBlock(KeyError):
    pass


def read_blocks(log_path):
    """All blocks of a freeze log, in file order."""
    blocks = []
    current = None
    for line in Path(log_path).read_text(encoding="utf-8").splitlines():
        if line.startswith("=== FREEZE "):
            words = line.split()
            utc = words[3][len("utc="):] if len(words) > 3 and words[3].startswith("utc=") else None
            current = {"name": words[2], "utc": utc, "reason": None, "files": []}
        elif line.startswith("=== END"):
            if current is not None:
                blocks.append(current)
            current = None
        elif current is not None:
            if line.startswith("reason: "):
                current["reason"] = line[len("reason: "):]
            elif len(line) > 66 and line[64:66] == "  ":
                current["files"].append((line[:64], line[66:]))
    return blocks


def last_block(root, name, log_name=LOG_NAME):
    blocks = [block for block in read_blocks(Path(root) / log_name) if block["name"] == name]
    if not blocks:
        raise NoSuchBlock(name)
    return blocks[-1]


def check(root, name, log_name=LOG_NAME):
    """Compare the files of the last block called `name` with the files on disk.

    Returns a list of (path, matches). Raises NoSuchBlock when there is no block.
    """
    root = Path(root)
    result = []
    for digest, relative in last_block(root, name, log_name)["files"]:
        path = root / relative
        result.append((relative, path.is_file() and sha256_file(path) == digest))
    return result


def write_block(root, name, files, reason, log_name=LOG_NAME, utc=None):
    """Append a block for `files` (paths relative to `root`) and return its text."""
    root = Path(root)
    if not name or len(name.split()) != 1:
        raise ValueError("a block name is one word without spaces")
    missing = [relative for relative in files if not (root / relative).is_file()]
    if missing:
        raise FileNotFoundError("cannot freeze missing file(s): " + ", ".join(missing))
    utc = utc or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = ["=== FREEZE %s utc=%s" % (name, utc), "reason: " + " ".join(reason.split())]
    lines += ["%s  %s" % (sha256_file(root / relative), relative) for relative in files]
    lines.append("=== END")
    text = "\n".join(lines) + "\n"
    log = root / log_name
    separator = "\n" if log.is_file() and log.stat().st_size else ""
    with open(log, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(separator + text)
    return text


def check_list(list_path, root=None):
    """Check a plain list of `<sha256>  <path>` lines. Returns a list of (path, matches)."""
    list_path = Path(list_path)
    root = Path(root) if root else list_path.parent
    result = []
    for line in list_path.read_text(encoding="utf-8").splitlines():
        if len(line) > 66 and line[64:66] in ("  ", " *"):
            path = root / line[66:]
            result.append((line[66:], path.is_file() and sha256_file(path) == line[:64]))
    return result
