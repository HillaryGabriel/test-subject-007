import os, tempfile, tkinter as tk, unittest
from pathlib import Path
from unittest.mock import patch
from test_subject_007.gui import App
from test_subject_007.case import Case

class WorkspaceGuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'TS007_HOME':str(self.root/'app')});self.env.start()
        try:self.app=App(auto_discover=False);self.app.update()
        except tk.TclError as e:self.env.stop();self.temp.cleanup();self.skipTest(str(e))
    def tearDown(self):
        if self.app.case:self.app.case.close()
        self.app.destroy();self.env.stop();self.temp.cleanup()
    def catalog(self):
        self.app.catalog={'version':'synthetic','unavailable':[],'plugins':[
            {'name':'windows.info.Info','options':[],'description':'Synthetic'},
            {'name':'windows.cmdline.CmdLine','options':[],'description':'Synthetic'},
            {'name':'windows.registry.printkey.PrintKey','options':[{'name':'key','flag':'--key','kind':'str','required':False,'default':None,'description':'Key'}],'description':'Synthetic'}]}
        self.app.filter_plugins()
    def case(self):
        image=self.root/'capture.raw';image.write_bytes(b'SYNTHETIC')
        case=Case.create(self.root/'cases',image,'UI test','Tester','Windows');self.app.install_case(case)
    def test_checkboxes_survive_search_filter(self):
        self.catalog();self.app.toggle_plugin('windows.cmdline.CmdLine')
        self.app.plugin_search.set('info');self.app.update()
        self.assertIn('windows.cmdline.CmdLine',self.app.checked_plugins)
        self.app.plugin_search.set('');self.app.update()
        self.assertIn('1 plugins',self.app.selection_label.cget('text'))
    def test_preset_selects_installed_only_and_reports_missing(self):
        self.catalog();self.app.profile_var.set('Malware investigation');self.app.apply_profile(quiet=True)
        self.assertIn('windows.info.Info',self.app.checked_plugins)
        self.assertIn('windows.filescan',self.app.profile_missing)
        self.assertNotIn('windows.filescan.FileScan',self.app.checked_plugins)
    def test_run_checked_expands_registry_keys(self):
        self.catalog();self.case()
        self.app.profile_var.set('Persistence investigation');self.app.apply_profile(quiet=True)
        self.app.checked_plugins={'windows.registry.printkey.PrintKey'};self.app.profile_missing=[]
        with patch.object(self.app,'run_batch') as run:
            self.app.run_checked()
        items=run.call_args.args[0];self.assertEqual(len(items),4)
        self.assertTrue(all('--key' in args for p,args in items))
    def test_live_pause_only_pauses_view_and_filter_can_replay(self):
        self.app.pause_log.set(True)
        self.app.append_live({'source':'stderr','text':'UNIQUE-LIVE-MARKER\n'})
        self.assertNotIn('UNIQUE-LIVE-MARKER',self.app.live_text.get('1.0','end'))
        self.assertEqual(len(self.app.live_blocks),1)
        self.app.pause_log.set(False);self.app.render_live()
        self.assertIn('UNIQUE-LIVE-MARKER',self.app.live_text.get('1.0','end'))
        self.app.log_source.set('Result CSV');self.app.render_live()
        self.assertNotIn('UNIQUE-LIVE-MARKER',self.app.live_text.get('1.0','end'))
    def test_findings_filter_and_detail_references(self):
        f={'id':'F-001','priority':'High','category':'Persistence','title':'SYNTHETIC Startup item','pid':42,'process':'demo.exe',
            'status':'Needs validation','observation':'demo.exe','context':'Synthetic','interpretation':'Not a malware verdict','action':'Validate',
            'references':[{'plugin':'windows.cmdline.CmdLine','run_id':'fixture','row_id':7}]}
        self.app.refresh_findings({'analysis_logic':'evidence-led','findings':[f],'quality_flags':[]})
        self.app.finding_tree.selection_set('F-001');self.app.show_finding()
        self.assertIn('row 7',self.app.finding_detail.get('1.0','end'))
        self.app.finding_search.set('not-present');self.assertEqual(len(self.app.finding_tree.get_children()),0)
    def test_live_progress_is_stage_specific_and_elapsed_visible(self):
        self.app.live_progress({'elapsed':65,'percent':15.11,'phase':'PDB scan','quiet_seconds':8,'bytes_written':5000})
        self.assertEqual(self.app.execution_time.get(),'01:05')
        self.assertIn('PDB scan',self.app.phase_var.get())
        self.assertIn('no new output',self.app.phase_var.get())
