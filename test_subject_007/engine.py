"""Subprocess analysis, cancellation, triage profiles, and reproducible run records."""
from __future__ import annotations
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from . import __version__
from .case import Case
from .live import LiveFiles
from .results import index_csv
from .diagnostics import diagnose
from .paths import inspect_image
from .util import Cancelled, atomic_json, data_root, fingerprint, hash_file, tail_text, utc_now


@dataclass
class Settings:
    symbols: str = ""
    offline: bool = True
    timeout_seconds: int = 0
    verify_after_batch: bool = True
    export_dir: str = ""
    auto_export: bool = True

    def normalized(self) -> "Settings":
        path = Path(self.symbols or data_root() / "symbols").expanduser().resolve()
        if ";" in str(path):
            raise ValueError("The symbol folder cannot contain a semicolon (Volatility uses it as a separator).")
        path.mkdir(parents=True, exist_ok=True)
        for system in ("windows", "linux", "mac"):
            (path / system).mkdir(exist_ok=True)
        timeout = int(self.timeout_seconds)
        if timeout < 0:
            raise ValueError("Timeout must be zero (unlimited) or a positive number of seconds.")
        return replace(self, symbols=str(path), offline=bool(self.offline), timeout_seconds=timeout,
                       verify_after_batch=bool(self.verify_after_batch))


def worker_prefix() -> list[str]:
    return [sys.executable, "-m", "test_subject_007.volworker"]


def subprocess_env() -> dict:
    env = os.environ.copy()
    package_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = package_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.update(PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1", PYTHONUTF8="1")
    return env


def child_options() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


def discover_plugins(timeout: int = 120) -> dict:
    result = subprocess.run([*worker_prefix(), "catalog"], shell=False,
                            capture_output=True, text=True, encoding="utf-8", errors="replace",
                            env=subprocess_env(), timeout=timeout, **child_options())
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Volatility plugin discovery failed.")
    data = json.loads(result.stdout)
    if not isinstance(data.get("plugins"), list):
        raise ValueError("Invalid plugin catalog returned by Volatility.")
    return data


# Shared by the planner, single-plugin and custom-queue execution paths.
from .options import plugin_arguments


def build_command(image: Path, output: Path, plugin: str, arguments: list[str],
                  settings: Settings, cache: Path, prefix: list[str] | None = None) -> list[str]:
    if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+", plugin):
        raise ValueError("Select a fully qualified plugin from the catalog.")
    # Plugin arguments are always separate argv elements, never a shell command.
    command = [*(prefix or worker_prefix()), "run", "--parallelism", "off", "-v", "-r", "csv",
               "-f", str(image), "-o", str(output), "--cache-path", str(cache),
               "-s", settings.symbols, "-l", str(output.parent / "volatility.log"),
               "--save-config", str(output.parent / "engine-config.json")]
    if settings.offline:
        command.append("--offline")
    return [*command, plugin, *arguments]


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass


def run_plugin(case: Case, plugin: str, arguments: list[str], settings: Settings,
               engine_version: str, cancel: threading.Event, emit=lambda *_: None,
               prefix: list[str] | None = None) -> dict:
    settings = settings.normalized()
    case.check_source()
    inspect_image(case.image)
    before = fingerprint(case.image)
    run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    folder = case.root / "runs" / run_id
    artifacts = folder / "artifacts"
    artifacts.mkdir(parents=True, mode=0o700)
    # Separate cache per case avoids simultaneous cache writers across cases.
    cache = case.root / "symbol-cache"
    cache.mkdir(exist_ok=True)
    command = build_command(case.image, artifacts, plugin, arguments, settings, cache, prefix)
    run = {"id": run_id, "plugin": plugin, "arguments": arguments, "command_argv": command,
           "app_version": __version__, "volatility_version": engine_version,
           "python_version": sys.version, "host_platform": sys.platform,
           "started_utc": utc_now(), "finished_utc": None, "status": "running",
           "offline": settings.offline, "symbol_directory": settings.symbols,
           "timeout_seconds": settings.timeout_seconds, "image_sha256": case.metadata["sha256"],
           "rows": 0, "exit_code": None, "error": "", "index_error": "",
           "source_fingerprint_before": before}
    atomic_json(folder / "run.json", run)
    case.audit("run_started", {"run_id": run_id, "plugin": plugin, "argv": command})
    emit("run_started", run)
    process = None
    start = time.monotonic()
    status = "failed"
    live = LiveFiles(folder, run_id, plugin, emit)
    try:
        with (folder / "stdout.csv").open("wb") as stdout, (folder / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen(command, shell=False, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, cwd=folder,
                                       env=subprocess_env(), **child_options())
            while process.poll() is None:
                elapsed = time.monotonic() - start
                emit("run_progress", {"run_id": run_id, "plugin": plugin,
                                      "elapsed": elapsed, **live.poll()})
                if cancel.is_set():
                    status = "cancelled"
                    terminate_process(process)
                    break
                if settings.timeout_seconds and elapsed >= settings.timeout_seconds:
                    status = "timed_out"
                    terminate_process(process)
                    break
                time.sleep(0.3)
            code = process.wait(timeout=10)
            run["exit_code"] = code
            if status not in ("cancelled", "timed_out"):
                status = "completed" if code == 0 else "failed"
        live.poll(final=True)
        emit("status", "Indexing results on disk...")
        count, columns, error = index_csv(folder / "stdout.csv", folder / "results.sqlite", cancel=cancel)
        run.update(rows=count, columns=columns, index_error=error)
        if cancel.is_set():
            status = "cancelled"
        elif error and status == "completed":
            status = "partial"
        if status == "completed":
            # Warnings should not be silently presented as a clean forensic result.
            with (folder / "stderr.log").open(encoding="utf-8", errors="replace") as stream:
                if any(re.search(r"\b(?:WARNING|ERROR|CRITICAL)\b", line) for line in stream):
                    status = "completed_with_warnings"
        after = fingerprint(case.image)
        run["source_fingerprint_after"] = after
        run["source_metadata_unchanged"] = before == after
        if before != after:
            status = "integrity_warning"
            run["error"] = "Source metadata changed during analysis. Verify the full SHA-256; do not rely on these results."
        emit("status", "Recording output hashes...")
        inventory = []
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.name != "run.json" and not path.is_symlink():
                inventory.append({"path": str(path.relative_to(folder)), "size": path.stat().st_size,
                                  "sha256": None if cancel.is_set() else hash_file(path, cancel)})
        run["output_files"] = inventory
    except Cancelled:
        run["error"] = "Cancelled while recording output hashes. Raw output is preserved; inventory may be incomplete."
        status = "cancelled"
    except Exception as exc:
        run["error"] = str(exc)
        status = "failed"
    finally:
        if process and process.poll() is None:
            terminate_process(process)
        live.poll(final=True)
        run.update(status=status, finished_utc=utc_now(), elapsed_seconds=round(time.monotonic() - start, 2))
        run["diagnosis"] = diagnose(run, folder)
        if status not in ("completed", "completed_with_warnings") and not run.get("error"):
            run["error"] = run["diagnosis"]["title"]
        atomic_json(folder / "run.json", run)
        case.audit("run_finished", {"run_id": run_id, "status": status,
                                    "rows": run["rows"], "exit_code": run["exit_code"],
                                    "run_metadata_sha256": hash_file(folder / "run.json")})
        emit("run_finished", run)
    return run


TRIAGE = {
    "Windows": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan",
                "windows.cmdline", "windows.netscan", "windows.dlllist", "windows.malware.malfind|windows.malfind"],
    "Linux": ["banners", "linux.pslist", "linux.pstree", "linux.bash", "linux.lsmod", "linux.sockstat"],
    "macOS": ["banners", "mac.pslist", "mac.pstree", "mac.lsmod"],
    "Unknown": ["banners"],
}


def triage_plugins(catalog: dict, evidence_os: str) -> tuple[list[dict], list[str]]:
    output, missing = [], []
    for candidate in TRIAGE.get(evidence_os, TRIAGE["Unknown"]):
        match = None
        for name in candidate.split("|"):
            match = next((p for p in catalog["plugins"] if p["name"].rsplit(".", 1)[0] == name), None)
            if match:
                break
        if match:
            output.append(match)
        else:
            missing.append(candidate)
    return output, missing
