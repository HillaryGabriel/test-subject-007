"""Small, dependency-free filesystem and integrity utilities."""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

class Cancelled(Exception):
    """The analyst requested cancellation."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def data_root() -> Path:
    override = os.environ.get("TS007_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TestSubject007"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "test-subject-007"


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def fingerprint(path: Path) -> dict:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Select a regular, acquired memory-image file, not a device or directory.")
    if info.st_size == 0:
        raise ValueError("The selected memory image is empty.")
    return {"size": info.st_size, "mtime_ns": info.st_mtime_ns,
            "device": info.st_dev, "inode": info.st_ino}


def hash_file(path: Path, cancel: threading.Event | None = None,
              progress: Callable[[float], None] | None = None) -> str:
    total = path.stat().st_size
    done = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            if cancel and cancel.is_set():
                raise Cancelled("Operation cancelled.")
            chunk = stream.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            done += len(chunk)
            if progress:
                progress(min(100.0, done * 100.0 / max(1, total)))
    return digest.hexdigest()


def slug(text: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_-]+", "-", text.strip()).strip("-")[:60]
    return result or "case"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.1f} {unit}"
        value /= 1024
    return str(size)


def tail_text(path: Path, limit: int = 65536) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as stream:
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(max(0, length - limit))
        text = stream.read().decode("utf-8", errors="replace").replace("\r", "\n")
    return ("[Earlier log content omitted from preview]\n" if length > limit else "") + text


class FileLock:
    """OS-level advisory lock; the file stays in place to avoid unlink races."""
    def __init__(self, path: Path):
        self.path = path
        self.stream = None

    def acquire(self) -> None:
        self.stream = self.path.open("a+b")
        try:
            # Do not read an already-locked byte: Windows range locks can deny it.
            if os.fstat(self.stream.fileno()).st_size == 0:
                self.stream.write(b"0")
                self.stream.flush()
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            self.stream = None
            raise RuntimeError("This case is already open in another application instance.") from exc

    def close(self) -> None:
        if self.stream:
            try:
                self.stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            finally:
                self.stream.close()
                self.stream = None
