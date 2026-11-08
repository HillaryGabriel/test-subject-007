"""Real Tk controls exercised under Xvfb; analysis workers are not invoked here."""
from __future__ import annotations
import os
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch
from test_subject_007.gui import App
from test_subject_007.case import Case
from test_subject_007.preflight_ui import PlanReview
from test_subject_007.profiles import COMPLETE
from test_subject_007.planning import build_plan
from tests.test_planning import fixture_catalog, plugin, spec


class PreflightGuiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{'TS007_HOME':str(self.root/'app')});self.env.start()
        try:self.app=App(auto_discover=False);self.app.update()
        except tk.TclError as exc:self.env.stop();self.tmp.cleanup();self.skipTest(str(exc))
        self.app.catalog=fixture_catalog();self.app.filter_plugins()
        image=self.root/'synthetic.raw';image.write_bytes(b'SYNTHETIC')
        self.app.install_case(Case.create(self.root/'cases',image,'Synthetic preflight UI','Tester','Windows'))
        self.app.profile_var.set('Custom');self.app.profile_changed()

    def tearDown(self):
        if self.app.case:self.app.case.close()
        self.app.destroy();self.env.stop();self.tmp.cleanup()

    def test_select_all_runs_ready_only_after_confirmation(self):
        self.app.select_shown()
        with patch.object(self.app,'review_plan',return_value=('run',None)) as review, patch.object(self.app,'run_batch') as run:
            self.app.run_checked()
        self.assertTrue(review.called)
        self.assertEqual(len(run.call_args.args[0]),101)
        self.assertEqual(len(run.call_args.kwargs['preflight']['deferred']),4)
        self.assertEqual(len(self.app.checked_plugins),105)

    def test_cancel_does_not_start_or_change_case_metadata(self):
        self.app.select_shown();before=self.app.case.metadata.copy()
        with patch.object(self.app,'review_plan',return_value=None),patch.object(self.app,'run_batch') as run:
            self.app.run_checked()
        run.assert_not_called();self.assertEqual(self.app.case.metadata,before)

    def test_configure_opens_the_correct_plugin_not_info(self):
        target='windows.pe_symbols.PESymbols';self.app.select_shown()
        with patch.object(self.app,'review_plan',return_value=('configure',target)),patch.object(self.app,'run_batch') as run:
            self.app.run_checked()
        run.assert_not_called();self.assertEqual(self.app.current_plugin['name'],target)
        self.assertIn('source',self.app.option_vars)

    def test_custom_apply_does_not_clear_checks_or_values(self):
        self.app.checked_plugins={'windows.pslist.PsList'}
        self.app.saved_plugin_values={'windows.pslist.PsList':{'pid':'4'}}
        self.app.apply_profile()
        self.assertEqual(self.app.checked_plugins,{'windows.pslist.PsList'})
        self.assertEqual(self.app.saved_plugin_values['windows.pslist.PsList'],{'pid':'4'})

    def test_cleared_option_is_not_silently_restored(self):
        target='windows.pe_symbols.PESymbols'
        self.app.configure_planned_plugin(target)
        self.app.option_vars['source'].set('processes');self.app.option_vars['module'].set('ntdll.dll')
        self.app.option_vars['symbols'].set('NtCreateFile');self.app.save_plugin_options()
        self.app.option_vars['module'].set('')
        self.app.configure_planned_plugin('windows.info.Info')
        self.assertEqual(self.app.saved_plugin_values[target]['module'],'')
        self.app.checked_plugins={target};plan=self.app.make_plan()
        self.assertIn('--module',plan.deferred[0]['reason'])

    def test_default_printkey_widgets_do_not_override_complete_queries(self):
        p=plugin('windows.registry.printkey.PrintKey',spec('key'),spec('recurse','bool',default=False))
        self.app.catalog['plugins'].append(p);self.app.filter_plugins()
        self.app.profile_var.set(COMPLETE);self.app.apply_profile(quiet=True)
        self.app.configure_planned_plugin(p['name'])
        self.app.configure_planned_plugin('windows.info.Info')
        self.assertNotIn(p['name'],self.app.saved_plugin_values)
        self.app.checked_plugins={p['name']};plan=self.app.make_plan()
        self.assertEqual(len(plan.items),4)

    def test_dialog_shows_missing_fields_and_can_configure(self):
        plan=build_plan(self.app.catalog,['windows.pe_symbols.PESymbols','windows.info.Info'],{},'Custom','Windows')
        dialog=PlanReview(self.app,plan);self.app.update()
        self.assertIn('--source',dialog.issue_detail.get('1.0','end'))
        self.assertIn('--module',dialog.issue_detail.get('1.0','end'))
        dialog.configure_selected()
        self.assertEqual(dialog.result,('configure','windows.pe_symbols.PESymbols'))

    def test_empty_ready_list_disables_run_button(self):
        plan=build_plan(self.app.catalog,['windows.pe_symbols.PESymbols'],{},'Custom','Windows')
        dialog=PlanReview(self.app,plan);self.app.update()
        self.assertEqual(str(dialog.run_button.cget('state')),'disabled')
        dialog.cancel();self.assertIsNone(dialog.result)

    def test_execution_lists_deferred_as_not_run(self):
        plan=build_plan(self.app.catalog,['windows.info.Info','windows.pe_symbols.PESymbols'],{},'Custom','Windows')
        self.app.prepare_execution(plan.items,plan.record())
        states=[self.app.execution_tree.item(k,'values')[1] for k in self.app.execution_tree.get_children()]
        self.assertEqual(states,['Queued','Not run / input'])
        self.assertIn('NOT RUN: windows.pe_symbols.PESymbols',self.app.live_text.get('1.0','end'))
        self.assertEqual(len(self.app.execution_plan),1)
