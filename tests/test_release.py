"""Branding, migration, configuration and packaging regression checks."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_subject_007 import APP_NAME, __version__
from test_subject_007.case import Case, verify_audit
from test_subject_007.engine import build_command, Settings, worker_prefix
from test_subject_007.exporting import export_report
from test_subject_007.util import atomic_json, data_root, hash_file


class ReleaseTests(unittest.TestCase):
    def test_brand_and_version(self):
        self.assertEqual(APP_NAME, 'Test Subject 007')
        self.assertEqual(__version__, '0.0.0')  # internal packaging placeholder, not a release label

    def test_worker_uses_renamed_module(self):
        self.assertEqual(worker_prefix()[-1], 'test_subject_007.volworker')

    def test_new_environment_override(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'TS007_HOME': folder}):
            self.assertEqual(data_root(), Path(folder).resolve())

    def test_schema_one_case_is_reopened_without_rehashing_or_rewriting_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image = root/'capture.raw'
            image.write_bytes(b'synthetic evidence for migration test')
            original_hash = hash_file(image)
            case = Case.create(root/'cases', image, 'Existing case', 'Tester', 'Windows')
            case.metadata['app_version'] = '1.0.0'
            case.save()
            case_root = case.root
            before = case.metadata.copy()
            case.close()
            reopened = Case.open(case_root)
            try:
                self.assertEqual(reopened.metadata, before)
                self.assertEqual(hash_file(image), original_hash)
                self.assertTrue(verify_audit(case_root/'audit.jsonl')[0])
            finally:
                reopened.close()

    def test_report_uses_new_brand_and_neutral_theme(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image = root/'capture.raw'
            image.write_bytes(b'report fixture')
            case = Case.create(root/'cases', image, 'Report fixture', 'Tester', 'Linux')
            try:
                report = case.root/'exports/report.html'
                export_report(case, report)
                text = report.read_text()
                self.assertIn('TEST SUBJECT 007', text)
                self.assertIn('#101012', text)
                self.assertIn('@media print', text)
                self.assertNotIn('<script', text)
            finally:
                case.close()

    def test_renamed_worker_command_keeps_offline_and_separate_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            command=build_command(root/'capture.raw', root/'out', 'windows.pslist.PsList',
                                  [], Settings(str(root/'symbols'), True), root/'cache')
            self.assertEqual(command[2], 'test_subject_007.volworker')
            self.assertIn('--offline', command)
            self.assertIn(str(root/'out'), command)

    def test_doctor_reports_dependency_absence_and_new_application_name(self):
        from test_subject_007.__main__ import doctor
        with patch('importlib.util.find_spec', return_value=None):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):
                result=doctor()
        detail=json.loads(stream.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(detail['application'], APP_NAME)
        self.assertEqual(detail['application_version'], __version__)
        self.assertFalse(detail['volatility_importable'])


if __name__ == '__main__':
    unittest.main()
