"""No remote operations: publication safety checks use temporary synthetic files."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('publisher',Path(__file__).resolve().parents[1]/'scripts/publish_github.py')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

class PublishingTests(unittest.TestCase):
    def test_manifest_is_an_allowlist(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'PUBLIC-FILES.txt').write_text('README.md\n')
            (root/'README.md').write_text('Synthetic source')
            (root/'evidence.dmp').write_text('Must not be published')
            self.assertEqual(publisher.source_files(root),['README.md'])
    def test_manifest_rejects_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):publisher.safe_path(Path(folder),'../secret.txt')
    def test_manifest_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'PUBLIC-FILES.txt').write_text('not-here.py\n')
            with self.assertRaises(ValueError):publisher.source_files(root)
    def test_manifest_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            # Mock for portability: Windows hosted runners need not grant symlink rights.
            real=Path.is_symlink
            def is_link(path):return path.name=='linked' or real(path)
            with patch.object(Path,'is_symlink',is_link):
                with self.assertRaises(ValueError):publisher.safe_path(root,'linked/readme.txt')
    def test_subprocess_failure_is_not_success(self):
        with patch.object(publisher.subprocess,'run') as mocked:
            mocked.return_value.returncode=1;mocked.return_value.stderr='authentication failed'
            with self.assertRaisesRegex(RuntimeError,'authentication failed'):publisher.run(['gh','auth','status'])
