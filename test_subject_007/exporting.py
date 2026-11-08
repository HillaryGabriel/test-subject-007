"""Safe analyst exports. Original plugin output remains untouched."""
from __future__ import annotations
import csv
import html
import json
import os
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from .case import Case, verify_audit
from .results import connect_read, iter_rows, query_rows
from .util import hash_file, utc_now


def safe_destination(case: Case, destination: Path) -> Path:
    destination = destination.expanduser().resolve()
    if destination == case.image.resolve():
        raise ValueError("An export must never overwrite the evidence image.")
    if destination.exists() and case.image.exists() and os.path.samefile(destination, case.image):
        raise ValueError("This export path refers to the evidence image.")
    try:
        relative = destination.relative_to(case.root)
    except ValueError:
        relative = None
    if relative is not None and (not relative.parts or relative.parts[0] != "exports"):
        raise ValueError("Save exports under the case's exports folder or outside the case, not over case records.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


@contextmanager
def export_stream(case: Case, destination: Path):
    destination = safe_destination(case, destination)
    fd, tmp = tempfile.mkstemp(prefix=".export-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def safe_csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    # Protect spreadsheet users from formula execution in attacker-controlled fields.
    # This affects only the analyst export, never the raw Volatility output.
    stripped = text.lstrip()
    if (stripped and stripped[0] in "=+-@") or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def export_results(case: Case, run_id: str, destination: Path, mode: str) -> int:
    if run_id not in {r["id"] for r in case.runs()}:
        raise ValueError("Select an existing run.")
    database = case.root / "runs" / run_id / "results.sqlite"
    if not database.is_file():
        raise ValueError("This run has no indexed results. Its raw output and log may still be available.")
    with closing(connect_read(database)) as conn:
        columns = json.loads(conn.execute("SELECT value FROM meta WHERE key='columns'").fetchone()[0])
    count = 0
    with export_stream(case, destination) as stream:
        if mode == "csv":
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(columns)
            for _, row in iter_rows(database):
                writer.writerow([safe_csv_cell(row.get(key, "")) for key in columns])
                count += 1
        elif mode == "json":
            stream.write("[\n")
            for _, row in iter_rows(database):
                if count:
                    stream.write(",\n")
                stream.write(json.dumps(row, ensure_ascii=False))
                count += 1
            stream.write("\n]\n")
        else:
            raise ValueError("Supported export formats: csv, json.")
    case.audit("results_exported", {"run_id": run_id, "format": mode, "rows": count,
                                    "destination": str(destination), "sha256": hash_file(destination)})
    return count


def export_report(case: Case, destination: Path, preview_limit: int = 200) -> None:
    """Compatibility entry point; destination suffix chooses PDF or HTML."""
    from .summary import build_summary
    from .reports import write_html, write_pdf
    model = build_summary(case)
    if destination.suffix.lower() == ".pdf":
        write_pdf(case, destination, model)
    elif destination.suffix.lower() in (".html", ".htm"):
        write_html(case, destination, model)
    else:
        raise ValueError("Choose a .pdf or .html report filename.")
    case.audit("report_exported", {"destination": str(destination), "sha256": hash_file(destination),
                                    "audit_head_in_report": model["audit_head"]})
