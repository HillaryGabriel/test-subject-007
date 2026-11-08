"""Optional REAL Volatility smoke tests. Skipped when dependency is unavailable.

These use synthetic bytes, not a real OS memory image. Passing them does not
replace Windows/Linux acceptance testing on known-good acquired images.
"""
import importlib.util
import tempfile
import threading
import unittest
from pathlib import Path
from test_subject_007.case import Case
from test_subject_007.engine import Settings, discover_plugins, run_plugin


@unittest.skipUnless(importlib.util.find_spec("volatility3"), "Volatility 3 is not installed")
class RealEngineTests(unittest.TestCase):
    def test_installed_catalog(self):
        catalog = discover_plugins()
        names = {p["name"] for p in catalog["plugins"]}
        self.assertIn("windows.pslist.PsList", names)
        self.assertIn("linux.pslist.PsList", names)
        self.assertIn("banners.Banners", names)
        from test_subject_007.planning import build_plan
        from test_subject_007.profiles import COMPLETE, resolve
        windows = [name for name in names if name.startswith("windows.")]
        plan = build_plan(catalog, windows, {}, "Custom", "Windows")
        self.assertIn("windows.info.Info", plan.ready_plugins)
        self.assertEqual(set(windows), plan.ready_plugins | {x["plugin"] for x in plan.deferred})
        if "windows.pe_symbols.PESymbols" in names:
            self.assertTrue(any(x["plugin"] == "windows.pe_symbols.PESymbols" and "--source" in x["reason"] for x in plan.deferred))
        chosen, missing = resolve(catalog, "Windows", COMPLETE)
        broad = build_plan(catalog, [p["name"] for p in chosen], {}, COMPLETE, "Windows", missing)
        self.assertGreater(len(broad.items), 10)

    def test_invalid_windows_image_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image = root / "not-a-real-memory-image.raw"
            image.write_bytes(b"\x00" * (1024 * 1024))
            case = Case.create(root / "cases", image, "Engine smoke test", "Test runner", "Windows")
            try:
                settings = Settings(str(root / "symbols"), True, 90, False)
                run = run_plugin(case, "windows.info.Info", [], settings,
                                 discover_plugins()["version"], threading.Event())
                self.assertEqual(run["status"], "failed", run)
                self.assertNotEqual(run["exit_code"], 0)
            finally:
                case.close()


if __name__ == "__main__":
    unittest.main()
