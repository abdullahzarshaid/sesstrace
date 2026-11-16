"""Small file helpers shared by the package.

Output files always use UTF-8 and LF line endings, on every platform, so that
their hashes do not depend on where they were written.
"""
import hashlib
import json
from pathlib import Path


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def write_json(path, value, indent=2, sort_keys=False):
    return write_text(path, json.dumps(value, indent=indent, sort_keys=sort_keys) + "\n")


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read_key_values(path):
    """Read a file of `key=value` lines into a dict; a missing file gives {}."""
    path = Path(path)
    if not path.is_file():
        return {}
    pairs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            pairs[key] = value
    return pairs


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()
