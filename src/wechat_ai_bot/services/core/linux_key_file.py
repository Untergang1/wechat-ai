"""Validated local credentials. Never include key material in diagnostics."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from .linux_sqlcipher import database_page1, verify_sqlcipher_page_hmac


class KeyFileError(ValueError):
    pass


@dataclass
class KeyFileResult:
    keys: dict[Path, str] = field(default_factory=dict, repr=False)
    invalid_count: int = 0
    error: str = ""

    def redacted(self):
        return {"source": "file", "valid_count": len(self.keys),
                "invalid_count": self.invalid_count, "error": self.error}


def read_document(path: Path) -> dict[str, str]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise KeyFileError("key_file requires a regular file with mode 0600")
            if info.st_uid not in (0, os.geteuid()):
                raise KeyFileError("key_file owner does not match service user or root")
            if info.st_size > 4 * 1024 * 1024:
                raise KeyFileError("key_file exceeds size limit")
            data = json.loads(stream.read(4 * 1024 * 1024 + 1))
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("keys"), dict):
            raise KeyFileError("key_file has an unsupported format")
        return data["keys"]
    except KeyFileError:
        raise
    except FileNotFoundError:
        raise KeyFileError("key_file is missing") from None
    except (OSError, ValueError, UnicodeError):
        raise KeyFileError("key_file cannot be read or parsed") from None


def validated_entry(root: Path, relative: str, value: str) -> tuple[Path, str]:
    if not isinstance(relative, str) or not isinstance(value, str):
        raise KeyFileError("invalid entry")
    part = PurePosixPath(relative)
    if part.is_absolute() or ".." in part.parts or part.as_posix() != relative or part.suffix != ".db":
        raise KeyFileError("invalid database path")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not re.fullmatch(r"[0-9a-fA-F]{96}", value):
        raise KeyFileError("invalid database path or key format")
    material = bytes.fromhex(value)
    page = database_page1(path)
    if page[:16] != material[32:] or not verify_sqlcipher_page_hmac(page, material[:32]):
        raise KeyFileError("database credential validation failed")
    return path, value.lower()


def load_key_file(path: Path, root: Path, databases) -> KeyFileResult:
    result = KeyFileResult()
    allowed = {Path(p).resolve(): Path(p) for p in databases}
    try:
        entries = read_document(path)
    except KeyFileError as exc:
        result.error = str(exc)
        return result
    for relative, value in entries.items():
        try:
            resolved, key = validated_entry(root, relative, value)
            if resolved not in allowed:
                raise KeyFileError("database is not currently discovered")
            result.keys[allowed[resolved]] = key
        except (KeyFileError, OSError):
            result.invalid_count += 1
    return result


def merge_key_file(path: Path, root: Path, incoming: dict[str, str]) -> int:
    """Atomically merge caller-verified entries; recheck HMAC before writing."""
    if path.is_symlink():
        raise KeyFileError("key_file cannot be a symlink")
    merged = {}
    if path.exists():
        for relative, value in read_document(path).items():
            try:
                _, valid = validated_entry(root, relative, value)
                merged[relative] = valid
            except (KeyFileError, OSError):
                continue
    for relative, value in incoming.items():
        _, valid = validated_entry(root, relative, value)
        merged[relative] = valid
    fd, temporary = tempfile.mkstemp(prefix=".database-keys-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"version": 1, "keys": merged}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise KeyFileError("key_file cannot be a symlink")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(merged)
