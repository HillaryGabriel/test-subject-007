"""Disk-backed result indexing; the interface only loads a page at a time."""
from __future__ import annotations
import csv
from contextlib import closing
import json
import sqlite3
from pathlib import Path

PAGE_SIZE = 200


def connect_read(path: Path) -> sqlite3.Connection:
    # A URI prevents an accidental read from creating an empty database.
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def index_csv(source: Path, database: Path, cancel=None) -> tuple[int, list[str], str]:
    """Preserve valid rows even when a run was cancelled or output is partial.

    Raw stdout.csv is never changed. Values in the normalized index are strings,
    exactly as represented by Volatility's CSV renderer, including hex addresses.
    """
    csv.field_size_limit(64 * 1024 * 1024)
    count, columns, error = 0, [], ""
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rows (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, searchable TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            DELETE FROM rows; DELETE FROM meta;
        """)
        try:
            with source.open(encoding="utf-8-sig", errors="strict", newline="") as stream:
                # Volatility CSV escapes backslashes, including in Windows paths.
                reader = csv.reader(stream, escapechar="\\", strict=True)
                for line in reader:
                    if not line:
                        continue
                    if line[0].startswith("Volatility 3 Framework"):
                        continue
                    if line[0] != "TreeDepth":
                        raise ValueError("No result table was produced. See Diagnostics for the original engine error.")
                    columns = line
                    break
                if not columns:
                    raise ValueError("No result table was produced. See Diagnostics for the original engine error.")
                if len(set(columns)) != len(columns):
                    raise ValueError("Duplicate CSV column names; raw output is preserved.")
                for line in reader:
                    if cancel and cancel.is_set():
                        error = "Indexing cancelled; raw output remains available."
                        break
                    if not line:
                        continue
                    if len(line) != len(columns):
                        raise ValueError(f"Incomplete CSV row after {count} valid records.")
                    payload = dict(zip(columns, line))
                    count += 1
                    conn.execute("INSERT INTO rows VALUES (?, ?, ?)",
                                 (count, json.dumps(payload, ensure_ascii=False),
                                  " \n ".join(line).casefold()))
                    if count % 5000 == 0:
                        conn.commit()
        except (ValueError, OSError, UnicodeError, csv.Error) as exc:
            error = str(exc)
        conn.executemany("INSERT INTO meta VALUES (?, ?)",
                         [("columns", json.dumps(columns)), ("row_count", str(count)),
                          ("index_error", error)])
    return count, columns, error


def query_rows(database: Path, query: str = "", page: int = 0,
               limit: int = PAGE_SIZE) -> tuple[list[str], list[tuple[int, dict]], int]:
    if page < 0 or limit < 1 or limit > 10000:
        raise ValueError("Invalid result page.")
    if not database.exists():
        return [], [], 0
    with closing(connect_read(database)) as conn:
        columns = json.loads(conn.execute("SELECT value FROM meta WHERE key='columns'").fetchone()[0])
        condition = "WHERE instr(searchable, ?) > 0" if query else ""
        args = [query.casefold()] if query else []
        total = conn.execute(f"SELECT count(*) FROM rows {condition}", args).fetchone()[0]
        rows = conn.execute(f"SELECT id, payload FROM rows {condition} ORDER BY id LIMIT ? OFFSET ?",
                            [*args, limit, page * limit])
        return columns, [(row[0], json.loads(row[1])) for row in rows], total


def iter_rows(database: Path):
    if not database.exists():
        return
    with closing(connect_read(database)) as conn:
        for row_id, payload in conn.execute("SELECT id, payload FROM rows ORDER BY id"):
            yield row_id, json.loads(payload)


def hunt_case(case, needle: str, limit: int = 500, cancel=None) -> tuple[list[dict], int]:
    if not needle.strip():
        raise ValueError("Enter a literal IP, domain, process name, hash, or other text.")
    found, total = [], 0
    for run in case.runs():
        if cancel and cancel.is_set():
            break
        database = case.root / "runs" / run["id"] / "results.sqlite"
        if not database.exists():
            continue
        _, rows, count = query_rows(database, needle, 0, max(1, min(500, limit - len(found))))
        total += count
        for row_id, record in rows:
            if len(found) < limit:
                found.append({"run_id": run["id"], "plugin": run["plugin"], "row_id": row_id,
                              "record": record})
    return found, total
