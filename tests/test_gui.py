"""Actual Tk widget tests; synthetic metadata and data are test fixtures only."""
from __future__ import annotations
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import tkinter as tk
from test_subject_007.case import Case
from test_subject_007.gui import App


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"TS007_HOME": str(Path(self.temp.name) / "appdata")})
        self.env.start()
        try:
            self.app = App(auto_discover=False)
            self.app.update()
        except tk.TclError as exc:
            self.env.stop()
            self.temp.cleanup()
            self.skipTest(f"A graphical display is not available: {exc}")
        self.messages = []
        self.patches = [patch(f"test_subject_007.gui.messagebox.{name}", side_effect=lambda *a, **kw: self.messages.append(a))
                        for name in ("showerror", "showwarning", "showinfo")]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in getattr(self, "patches", []):
            item.stop()
        if getattr(self, "app", None):
            if self.app.case:
                self.app.case.close()
            self.app.destroy()
        self.env.stop()
        self.temp.cleanup()

    def test_all_pages_render(self):
        for page in self.app.pages:
            self.app.show(page)
            self.app.update()
            self.assertTrue(self.app.pages[page].winfo_ismapped())
        self.assertEqual(len(self.app.pages), 8)
        self.assertIn("Evidence lab", self.app.pages)
        self.assertIn("Execution",self.app.pages)
        self.assertIn("Findings",self.app.pages)
        self.assertNotIn("IOC search", self.app.pages)
        self.app.geometry("1160x760")
        for page in self.app.pages:
            self.app.show(page)
            self.app.update()
            self.assertTrue(self.app.cancel_button.winfo_ismapped())
            bottom = self.app.cancel_button.winfo_rooty() + self.app.cancel_button.winfo_height()
            self.assertLessEqual(bottom, self.app.winfo_rooty() + self.app.winfo_height())

    def test_new_brand_theme_and_navigation_marker(self):
        from test_subject_007.theme import BG, RED, SIDE
        self.assertIn("Test Subject 007", self.app.title())
        self.assertEqual(self.app.cget("bg"), BG)
        self.app.show("Analyze")
        self.app.update()
        self.assertEqual(self.app.nav_markers["Analyze"].cget("bg"), RED)
        self.assertEqual(self.app.nav_markers["Overview"].cget("bg"), SIDE)

    def test_no_case_actions_are_disabled(self):
        self.assertTrue(all(str(button.cget("state")) == "disabled" for button in self.app.case_buttons))
        self.assertTrue(self.app.history_empty.winfo_ismapped())

    def test_engine_badge_is_actual_catalog_status(self):
        self.app.catalog_error = "dependency unavailable"
        self.app.update_diagnostics()
        self.assertIn("SETUP REQUIRED", self.app.engine_badge.get())
        self.app.catalog_error = ""
        self.app.catalog = {"version": "test-fixture", "plugins": [], "unavailable": []}
        self.app.update_diagnostics()
        self.assertNotIn("test-fixture", self.app.engine_badge.get())
        self.assertIn("READY", self.app.engine_badge.get())
        self.assertIn("0 PLUGINS", self.app.engine_badge.get())

    def test_short_window_scrolls_without_discarding_content(self):
        self.app.geometry("1160x760")
        for name in ("Overview", "Settings"):
            self.app.show(name)
            self.app.update()
            page = self.app.pages[name]
            self.assertGreaterEqual(page.body.winfo_height(), page.body.winfo_reqheight())
            page.canvas.yview_moveto(1.0)
            self.app.update()
            self.assertAlmostEqual(page.canvas.yview()[1], 1.0)

    def test_catalog_builds_dynamic_options(self):
        self.app.catalog = {"version": "synthetic", "unavailable": [], "plugins": [{
            "name": "windows.example.Example", "description": "Synthetic widget test.",
            "options": [{"name": "pid", "flag": "--pid", "kind": "list", "element_type": "int", "default": None,
                         "required": False, "description": "Select process IDs."},
                        {"name": "dump", "flag": "--dump", "kind": "bool", "default": False,
                         "required": False, "description": "Extract memory."}]}]}
        self.app.filter_plugins()
        self.app.plugin_tree.selection_set("windows.example.Example")
        self.app.select_plugin()
        self.app.option_vars["pid"].set("4, 128")
        self.app.option_vars["dump"].set(True)
        self.app.add_to_queue()
        self.assertEqual(self.app.queue_items[0][1], ["--pid", "4", "128", "--dump"])
        self.app.show("Analyze")
        self.app.update()
        self.assertFalse(self.messages)

    def test_case_switch_clears_previous_results(self):
        root = Path(self.temp.name)
        image = root / "test.raw"
        image.write_bytes(b"synthetic image")
        case = Case.create(root / "cases", image, "UI case", "Tester", "Linux")
        self.app.current_rows = {12: {"PID": "99"}}
        self.app.result_tree.insert("", "end", iid="12", values=["previous case"])
        self.app.install_case(case)
        self.assertEqual(self.app.current_rows, {})
        self.assertEqual(self.app.result_tree.get_children(), ())
        self.assertEqual(self.app.metrics["os"].cget("text"), "Linux")

    def test_background_task_returns_on_main_event_loop(self):
        received = []
        self.app.task(lambda cancel, emit: 42, received.append)
        deadline = time.monotonic() + 4
        while self.app.busy and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.02)
        self.assertEqual(received, [42])
        self.assertFalse(self.app.busy)

    def test_missing_engine_is_reported_not_faked(self):
        self.app.events.put(("catalog_error", "missing volatility3 - synthetic UI error test"))
        deadline = time.monotonic() + 3
        while not self.app.catalog_error and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.02)
        self.assertEqual(self.app.catalog["plugins"], [])
        self.assertIn("missing volatility3", self.app.diagnostics.get("1.0", "end"))

    def test_no_release_label_and_export_path_visible_at_minimum_size(self):
        from test_subject_007 import __version__
        self.assertNotIn(__version__,self.app.title())
        self.app.geometry("1160x760");self.app.update()
        self.assertTrue(self.app.last_export_var.get())
        self.assertTrue(self.app.export_dir_var.get())
        self.assertNotIn("IOC search",self.app.nav_buttons)
        self.assertIn("Observables",[self.app.result_tabs.tab(t,"text") for t in self.app.result_tabs.tabs()])

    def test_export_folder_can_be_pasted_saved_and_copied(self):
        destination=Path(self.temp.name)/"Chosen output with spaces"
        self.app.export_dir_var.set('"'+str(destination)+'"')
        self.app.save_export_folder()
        self.assertEqual(self.app.settings.export_dir, str(destination.resolve(strict=True)))
        self.assertTrue(destination.is_dir())
        self.app.copy_value(str(destination))
        self.assertEqual(self.app.clipboard_get(),str(destination))
        self.assertFalse(self.messages)

    def test_failed_batch_auto_exports_and_opens_diagnostics(self):
        import sys
        from test_subject_007.engine import run_plugin as real_runner
        from dataclasses import replace
        root=Path(self.temp.name)
        image=root/"test.raw";image.write_bytes(b"synthetic image bytes")
        case=Case.create(root/"cases",image,"UI failure test","Test analyst","Windows")
        self.app.install_case(case)
        self.app.settings=replace(self.app.settings,symbols=str(root/"symbols"),verify_after_batch=False,auto_export=True)
        self.app.export_dir_var.set(str(root/"Reports"))
        plugin={"name":"test.fail.Plugin","options":[]}
        self.app.catalog={"version":"SYNTHETIC","plugins":[plugin],"unavailable":[]}
        fixture=Path(__file__).parent/"fake_volworker.py"
        def wrapped(*args,**kwargs):
            return real_runner(*args,**kwargs,prefix=[sys.executable,str(fixture)])
        with patch("test_subject_007.gui.run_plugin",side_effect=wrapped),patch("test_subject_007.gui.ExportDialog") as dialog:
            self.app.run_batch([(plugin,[])])
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                self.app.update();time.sleep(.02)
                if not self.app.busy and self.app.last_export_folder:
                    break
            self.assertFalse(self.app.busy)
            self.assertTrue((self.app.last_export_folder/"report.pdf").is_file())
            self.assertTrue((self.app.last_export_folder/"report.html").is_file())
            self.assertTrue((self.app.last_export_folder/"results.csv").is_file())
            self.assertEqual(self.app.result_tabs.select(),str(self.app.diagnosis_page))
            self.assertEqual(list(self.app.result_tree.cget("columns")),["Result"])
            self.assertTrue(dialog.called)
            self.assertFalse(self.messages)


    def test_import_actions_remain_visible_at_dialog_minimum_size(self):
        from test_subject_007.dialogs import ImportDialog
        dialog=ImportDialog(self.app,self.app.settings,str(Path(self.temp.name)/'Reports'))
        try:
            dialog.geometry('760x700');self.app.update()
            bottom=dialog.accept_button.winfo_rooty()+dialog.accept_button.winfo_height()
            self.assertTrue(dialog.accept_button.winfo_ismapped())
            self.assertLessEqual(bottom,dialog.winfo_rooty()+dialog.winfo_height())
            dialog.scroller.canvas.yview_moveto(1);self.app.update()
            self.assertAlmostEqual(dialog.scroller.canvas.yview()[1],1.0)
        finally:
            dialog.destroy()


if __name__ == "__main__":
    unittest.main()
