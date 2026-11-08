from __future__ import annotations
import csv
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from test_subject_007.case import Case, verify_audit
from test_subject_007.engine import Settings, build_command, plugin_arguments, run_plugin, triage_plugins
from test_subject_007.exporting import export_report, export_results, safe_csv_cell, safe_destination
from test_subject_007.results import index_csv, query_rows, hunt_case
from test_subject_007.util import Cancelled, fingerprint, hash_file, slug

FIXTURE = Path(__file__).parent / "fake_volworker.py"


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "image with spaces.raw"
        self.image.write_bytes(b"SYNTHETIC MEMORY FIXTURE\x00" * 100)
        self.case = Case.create(self.root / "cases", self.image, "Test Case", "Test Analyst", "Windows")
        self.settings = Settings(str(self.root / "symbols"), True, 0, False)

    def tearDown(self):
        self.case.close()
        self.temp.cleanup()

    def execute(self, plugin="test.ok.Plugin", cancel=None, settings=None):
        return run_plugin(self.case, plugin, [], settings or self.settings,
                          "SYNTHETIC-TEST-ENGINE", cancel or threading.Event(),
                          prefix=[sys.executable, str(FIXTURE)])

    def test_hash_matches_hashlib(self):
        self.assertEqual(hash_file(self.image), hashlib.sha256(self.image.read_bytes()).hexdigest())

    def test_hash_cancel(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(Cancelled):
            hash_file(self.image, event)

    def test_empty_image_rejected(self):
        path = self.root / "empty.raw"
        path.touch()
        with self.assertRaises(ValueError):
            fingerprint(path)

    def test_directory_rejected(self):
        with self.assertRaises(ValueError):
            fingerprint(self.root)

    def test_slug_cannot_traverse(self):
        self.assertNotIn("/", slug("../../hostile path"))
        self.assertNotIn(".", slug("../../hostile path"))

    def test_import_never_changes_image(self):
        self.assertEqual(hash_file(self.image), self.case.metadata["sha256"])
        self.assertEqual(self.case.metadata["fingerprint"], fingerprint(self.image))

    def test_audit_chain(self):
        self.case.add_note("Observed test behavior")
        okay, count, _ = verify_audit(self.case.root / "audit.jsonl")
        self.assertTrue(okay)
        self.assertEqual(count, 2)

    def test_audit_tampering_rejected(self):
        path = self.case.root / "audit.jsonl"
        text = path.read_text().replace("Test Analyst", "Other Analyst")
        path.write_text(text)
        self.assertFalse(verify_audit(path)[0])
        with self.assertRaises(ValueError):
            self.case.audit("bad_append", {})

    def test_case_lock_prevents_parallel_open(self):
        with self.assertRaises(RuntimeError):
            Case.open(self.case.root)

    def test_case_reopen(self):
        root = self.case.root
        self.case.close()
        self.case = Case.open(root)
        self.assertEqual(self.case.metadata["name"], "Test Case")

    def test_changed_image_blocks_analysis(self):
        with self.image.open("ab") as stream:
            stream.write(b"different")
        with self.assertRaises(ValueError):
            self.case.check_source()
        self.assertFalse(self.case.verify_image())
        self.assertEqual(self.case.metadata["verification"], "mismatch")

    def test_relink_matching_image(self):
        moved = self.root / "relocated.raw"
        moved.write_bytes(self.image.read_bytes())
        self.assertTrue(self.case.verify_image(new_path=moved))
        self.assertEqual(self.case.image, moved.resolve(strict=True))

    def test_relink_wrong_image_retains_original(self):
        wrong = self.root / "wrong.raw"
        wrong.write_bytes(b"wrong")
        self.assertFalse(self.case.verify_image(new_path=wrong))
        self.assertEqual(self.case.image, self.image.resolve(strict=True))
        self.assertEqual(self.case.metadata["verification"], "matched")

    def test_plugin_argument_types_and_windows_paths(self):
        plugin = {"options": [
            {"name": "pid", "flag": "--pid", "kind": "list", "element_type": "int", "required": False},
            {"name": "dump", "flag": "--dump", "kind": "bool", "required": False},
            {"name": "file", "flag": "--file-input", "kind": "str", "required": True},
        ]}
        args = plugin_arguments(plugin, {"pid": "[4, 128]", "dump": True, "file": r"C:\Memory Files\a.yar"})
        self.assertEqual(args, ["--pid", "4", "128", "--dump", "--file-input", r"C:\Memory Files\a.yar"])
        with self.assertRaises(ValueError):
            plugin_arguments(plugin, {})

    def test_bad_integer_rejected(self):
        plugin = {"options": [{"name": "pid", "flag": "--pid", "kind": "int", "required": False}]}
        with self.assertRaises(ValueError):
            plugin_arguments(plugin, {"pid": "12; rm -rf /"})

    def test_command_separates_paths_and_offline_option(self):
        settings = self.settings.normalized()
        cmd = build_command(self.image, self.root / "output directory", "windows.pslist.PsList",
                            ["--pid", "123"], settings, self.root / "cache")
        self.assertIn(str(self.image), cmd)
        self.assertIn("--offline", cmd)
        self.assertEqual(cmd[-3:], ["windows.pslist.PsList", "--pid", "123"])
        with self.assertRaises(ValueError):
            build_command(self.image, self.root, "pslist;bad", [], settings, self.root)

    def test_synthetic_subprocess_success_and_artifact_hashes(self):
        run = self.execute()
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["rows"], 2)
        folder = self.case.root / "runs" / run["id"]
        for record in run["output_files"]:
            self.assertEqual(hash_file(folder / record["path"]), record["sha256"])
        self.assertTrue(run["source_metadata_unchanged"])

    def test_windows_paths_multiline_and_html_preserved(self):
        run = self.execute()
        _, rows, total = query_rows(self.case.root / "runs" / run["id"] / "results.sqlite")
        self.assertEqual(total, 2)
        self.assertEqual(rows[0][1]["Path"], r"C:\Program Files\Example\test.exe")
        self.assertIn("\nsecond line", rows[1][1]["Comment"])

    def test_failure_not_misreported_as_empty_success(self):
        run = self.execute("test.fail.Plugin")
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["exit_code"], 1)
        self.assertTrue(run["index_error"])

    def test_empty_valid_output_is_valid_zero_rows(self):
        run = self.execute("test.empty.Plugin")
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["rows"], 0)
        self.assertEqual(run["index_error"], "")

    def test_warning_visible(self):
        self.assertEqual(self.execute("test.warn.Plugin")["status"], "completed_with_warnings")

    def test_partial_csv_retains_valid_rows(self):
        run = self.execute("test.partial.Plugin")
        self.assertEqual(run["status"], "partial")
        self.assertEqual(run["rows"], 1)

    def test_source_change_during_run_detected(self):
        run = self.execute("test.change.Plugin")
        self.assertEqual(run["status"], "integrity_warning")
        self.assertFalse(run["source_metadata_unchanged"])

    def test_timeout_stops_real_subprocess(self):
        settings = Settings(self.settings.symbols, True, 1, False)
        run = self.execute("test.slow.Plugin", settings=settings)
        self.assertEqual(run["status"], "timed_out")
        self.assertLess(run["elapsed_seconds"], 15)

    def test_cancel_stops_real_subprocess(self):
        cancel = threading.Event()
        timer = threading.Timer(0.4, cancel.set)
        timer.start()
        try:
            run = self.execute("test.slow.Plugin", cancel)
        finally:
            timer.cancel()
        self.assertEqual(run["status"], "cancelled")
        self.assertLess(run["elapsed_seconds"], 15)

    def test_search_is_literal_and_case_insensitive(self):
        run = self.execute()
        db = self.case.root / "runs" / run["id"] / "results.sqlite"
        self.assertEqual(query_rows(db, "SYNTHETIC.EXE")[2], 1)
        self.assertEqual(query_rows(db, "%")[2], 0)
        self.assertEqual(query_rows(db, "' OR 1=1 --")[2], 0)
        matches, total = hunt_case(self.case, "example.exe")
        self.assertEqual(total, 1)
        self.assertEqual(matches[0]["plugin"], "test.ok.Plugin")

    def test_csv_sanitizes_formula_without_mutating_raw(self):
        run = self.execute()
        target = self.case.root / "exports" / "results.csv"
        export_results(self.case, run["id"], target, "csv")
        with target.open(newline="", encoding="utf-8") as stream:
            row = next(csv.DictReader(stream))
        self.assertEqual(row["Comment"], "'=1+1")
        raw = self.case.root / "runs" / run["id"] / "stdout.csv"
        self.assertIn("=1+1", raw.read_text())
        self.assertEqual(safe_csv_cell("  @sum(1)"), "'  @sum(1)")

    def test_json_export_preserves_exact_text(self):
        run = self.execute()
        target = self.case.root / "exports" / "results.json"
        count = export_results(self.case, run["id"], target, "json")
        self.assertEqual(count, 2)
        self.assertEqual(json.loads(target.read_text())[0]["Comment"], "=1+1")

    def test_html_report_escapes_attacker_content(self):
        self.execute()
        self.case.add_note("<script>malicious()</script>")
        target = self.case.root / "exports" / "report.html"
        export_report(self.case, target)
        text = target.read_text()
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("Content-Security-Policy", text)
        self.assertIn(self.case.metadata["sha256"], text)

    def test_export_cannot_overwrite_evidence_or_case(self):
        for destination in (self.image, self.case.root / "case.json", self.case.root / "audit.jsonl"):
            with self.assertRaises(ValueError):
                safe_destination(self.case, destination)

    def test_export_rejects_evidence_hardlink(self):
        target = self.root / "hardlink.csv"
        try:
            os.link(self.image, target)
        except OSError:
            self.skipTest("Hardlinks unavailable")
        with self.assertRaises(ValueError):
            safe_destination(self.case, target)

    def test_pagination(self):
        path = self.root / "large.csv"
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, escapechar="\\")
            writer.writerow(["TreeDepth", "PID"])
            writer.writerows((0, i) for i in range(511))
        db = self.root / "index.sqlite"
        count, _, error = index_csv(path, db)
        self.assertEqual(count, 511)
        self.assertFalse(error)
        _, rows, total = query_rows(db, page=2)
        self.assertEqual(len(rows), 111)
        self.assertEqual(total, 511)
        self.assertEqual(rows[0][1]["PID"], "400")

    def test_triage_resolves_current_plugin_names(self):
        catalog = {"plugins": [{"name": "windows.malware.malfind.Malfind"}, {"name": "windows.info.Info"}]}
        plugins, missing = triage_plugins(catalog, "Windows")
        self.assertIn("windows.malware.malfind.Malfind", [p["name"] for p in plugins])
        self.assertIn("windows.pslist", missing)

    def test_missing_database_does_not_create_file(self):
        path = self.root / "not-created.sqlite"
        self.assertEqual(query_rows(path), ([], [], 0))
        self.assertFalse(path.exists())

    def test_invalid_timeout_and_symbol_separator(self):
        with self.assertRaises(ValueError):
            Settings(str(self.root / "semi;colon")).normalized()
        with self.assertRaises(ValueError):
            Settings(str(self.root / "symbols"), timeout_seconds=-1).normalized()


if __name__ == "__main__":
    unittest.main()
