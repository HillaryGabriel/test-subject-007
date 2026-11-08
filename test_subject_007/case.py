"""Case metadata, evidence hashes, audit history, and analyst annotations."""
from __future__ import annotations
import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from . import __version__
from .util import FileLock, atomic_json, fingerprint, hash_file, slug, utc_now


def _event_hash(event: dict) -> str:
    return hashlib.sha256(json.dumps(event, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_audit(path: Path) -> tuple[bool, int, str]:
    previous = "0" * 64
    count = 0
    if not path.exists():
        return False, 0, "Audit file is missing."
    try:
        with path.open(encoding="utf-8") as stream:
            for count, line in enumerate(stream, 1):
                event = json.loads(line)
                claimed = event.pop("event_sha256")
                if event.get("previous_sha256") != previous or _event_hash(event) != claimed:
                    return False, count, f"Audit chain mismatch at event {count}."
                previous = claimed
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, count, str(exc)
    if count == 0:
        return False, 0, "Audit file is empty."
    return True, count, previous


class Case:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.lock = FileLock(self.root / ".case.lock")
        self.lock.acquire()
        self.mutex = threading.RLock()
        self.metadata: dict = {}

    @classmethod
    def create(cls, base: Path, image: Path, name: str, analyst: str,
               evidence_os: str, cancel=None, progress=None) -> "Case":
        image = image.expanduser().resolve(strict=True)
        before = fingerprint(image)
        if evidence_os not in ("Windows", "Linux", "macOS", "Unknown"):
            raise ValueError("Unsupported evidence OS selection.")
        root = base.expanduser().resolve() / (slug(name) + "-" + uuid.uuid4().hex[:8])
        root.mkdir(parents=True, mode=0o700)
        case = cls(root)
        try:
            for folder in ("runs", "exports"):
                (root / folder).mkdir(mode=0o700)
            digest = hash_file(image, cancel, progress)
            if fingerprint(image) != before:
                raise ValueError("Evidence changed while hashing. Use a stable forensic working copy.")
            case.metadata = {"schema": 1, "id": root.name, "name": name.strip() or image.stem,
                             "analyst": analyst.strip(), "created_utc": utc_now(),
                             "app_version": __version__, "evidence_os": evidence_os,
                             "image": str(image), "sha256": digest, "fingerprint": before,
                             "last_verified_utc": utc_now(), "verification": "matched"}
            case.save()
            atomic_json(root / "notes.json", [])
            case.audit("case_created", {"image": str(image), "sha256": digest,
                                        "fingerprint": before, "analyst": analyst})
            return case
        except BaseException:
            case.close()
            # Preserve partial case folder for troubleshooting, never touch the image.
            raise

    @classmethod
    def open(cls, root: Path) -> "Case":
        root = root.parent if root.is_file() else root
        if not (root / "case.json").is_file():
            raise ValueError("Select a case folder containing case.json.")
        case = cls(root)
        try:
            case.metadata = json.loads((case.root / "case.json").read_text(encoding="utf-8"))
            if case.metadata.get("schema") != 1:
                raise ValueError("This case schema is not supported.")
            for field in ("image", "sha256", "fingerprint", "name", "evidence_os"):
                if field not in case.metadata:
                    raise ValueError(f"Case metadata is missing {field}.")
            okay, _, detail = verify_audit(case.root / "audit.jsonl")
            if not okay:
                raise ValueError(f"Audit verification failed: {detail}. Preserve and inspect this case manually.")
            with (case.root / "audit.jsonl").open(encoding="utf-8") as stream:
                first = json.loads(next(stream))
            if (first.get("action") != "case_created" or
                    first.get("detail", {}).get("sha256") != case.metadata["sha256"]):
                raise ValueError("Case evidence hash does not match its original audit record.")
            # A previous process may have stopped without finalizing the run.
            for run in case.runs():
                if run["status"] == "running":
                    run.update(status="interrupted", finished_utc=utc_now(),
                               error="Previous application session ended during this run.")
                    atomic_json(case.root / "runs" / run["id"] / "run.json", run)
            case.audit("case_opened", {})
            return case
        except BaseException:
            case.close()
            raise

    @property
    def image(self) -> Path:
        return Path(self.metadata["image"])

    def save(self) -> None:
        with self.mutex:
            atomic_json(self.root / "case.json", self.metadata)

    def audit(self, action: str, detail: dict) -> None:
        with self.mutex:
            path = self.root / "audit.jsonl"
            previous = "0" * 64
            if path.exists():
                okay, _, previous = verify_audit(path)
                if not okay:
                    raise ValueError("Audit chain changed; refusing to append a misleading event.")
            event = {"utc": utc_now(), "action": action, "detail": detail,
                     "previous_sha256": previous}
            event["event_sha256"] = _event_hash(event)
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())

    def check_source(self) -> None:
        if self.metadata.get("verification") == "mismatch":
            raise ValueError("Evidence hash mismatch recorded. Restore the original image or create a separate case.")
        if fingerprint(self.image) != self.metadata["fingerprint"]:
            raise ValueError("Evidence file metadata changed. Use Verify SHA-256 before further analysis.")

    def verify_image(self, cancel=None, progress=None, new_path: Path | None = None) -> bool:
        target = (new_path or self.image).expanduser().resolve(strict=True)
        before = fingerprint(target)
        digest = hash_file(target, cancel, progress)
        if fingerprint(target) != before:
            raise ValueError("Image changed during verification; result is not reliable.")
        matches = digest == self.metadata["sha256"]
        detail = {"image": str(target), "actual_sha256": digest,
                  "expected_sha256": self.metadata["sha256"], "matched": matches}
        self.audit("image_relinked" if new_path and matches else "image_verified", detail)
        if matches:
            self.metadata.update(image=str(target), fingerprint=before,
                                 last_verified_utc=utc_now(), verification="matched")
        elif new_path is None:
            self.metadata.update(verification="mismatch", last_verified_utc=utc_now())
        self.save()
        return matches

    def runs(self) -> list[dict]:
        output = []
        for path in sorted((self.root / "runs").glob("*/run.json"), reverse=True):
            data = json.loads(path.read_text(encoding="utf-8"))
            # Prevent case metadata from pointing outside the local run directory.
            if data.get("id") != path.parent.name:
                raise ValueError("Invalid run identifier in case metadata.")
            output.append(data)
        return output

    def notes(self) -> list[dict]:
        path = self.root / "notes.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

    def add_note(self, text: str, run_id: str = "", row_id: int | None = None) -> None:
        if not text.strip():
            raise ValueError("A note cannot be empty.")
        with self.mutex:
            notes = self.notes()
            note = {"utc": utc_now(), "analyst": self.metadata["analyst"],
                    "run_id": run_id, "row_id": row_id, "text": text.strip()}
            notes.append(note)
            atomic_json(self.root / "notes.json", notes)
            self.audit("note_added", note)

    def close(self) -> None:
        self.lock.close()
