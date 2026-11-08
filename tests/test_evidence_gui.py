"""Real Tk evidence-lab controls. No engine invocation and no client data."""
import json
import os
from pathlib import Path
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch
from test_subject_007.gui import App
from test_subject_007.case import Case
from test_subject_007.profiles import GOALS
from test_subject_007.util import atomic_json

class EvidenceGuiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
        self.env=patch.dict(os.environ,{'TS007_HOME':str(self.root/'settings')});self.env.start()
        try:self.app=App(auto_discover=False);self.app.update()
        except tk.TclError as exc:
            self.env.stop();self.tmp.cleanup();self.skipTest(str(exc))
        self.img=self.root/'capture.raw';self.img.write_bytes(b'SYNTHETIC evidence')
        self.case=Case.create(self.root/'cases',self.img,'Lab demo','Test analyst','Windows')
        self.app.install_case(self.case)
    def tearDown(self):
        if getattr(self,'app',None):
            if self.app.case:self.app.case.close()
            self.app.destroy()
        self.env.stop();self.tmp.cleanup()
    def test_cards_do_not_display_effort_labels(self):
        self.assertTrue(all('effort' not in g for g in GOALS))
        self.assertTrue(any(g['title']=='Suspicious execution' for g in GOALS))
    def test_evidence_lab_tabs_accessible(self):
        self.app.show('Evidence lab');self.app.update()
        texts=[self.app.lab_tabs.tab(t,'text') for t in self.app.lab_tabs.tabs()]
        self.assertEqual(texts,['Processes & paths','Files & SHA-256','Timeline & logons','Analyst assessment'])
    def test_context_hidden_unless_requested(self):
        self.app.refresh_findings({'analysis_logic':'evidence-led','findings':[{'id':'F-001','priority':'Informational','category':'Remote access','pid':4,'title':'Remote context','layer':'Context'}],'actionable_count':0,'context_count':1})
        self.assertFalse(self.app.finding_tree.get_children())
        self.app.show_context_var.set(True);self.app.filter_findings();self.assertEqual(len(self.app.finding_tree.get_children()),1)
    def test_legacy_cached_noise_requires_rebuild(self):
        atomic_json(self.case.root/'analysis-summary.json',{'findings':[{'id':'old','category':'Java / scripts','title':'Legacy PATHEXT'}]})
        self.app.refresh_findings();self.assertFalse(self.app.finding_model)
        self.assertIn('Rebuild',self.app.finding_notice.cget('text'))
    def test_case_switch_clears_assessment_draft(self):
        self.app.assessment_reason.insert('1.0','Previous case draft')
        other=Case.create(self.root/'cases',self.img,'Second lab','Test analyst','Windows')
        self.app.install_case(other)
        self.assertEqual(self.app.assessment_reason.get('1.0','end-1c'),'')
        self.assertEqual(self.app.assessment_disposition.get(),'Unresolved')
    def test_copy_hash_uses_selected_actual_value(self):
        digest='a'*64
        self.app.refresh_findings({'analysis_logic':'evidence-led','binary_evidence':[{'pid':42,'representation':'acquired_file','sha256':digest,'integrity':'Verified copied bytes','reputation':'Not assessed'}]})
        self.app.binary_lab_tree.selection_set('0');self.app.copy_binary_hash()
        self.assertEqual(self.app.clipboard_get(),digest)
    def test_event_preview_shows_typed_times(self):
        self.app.refresh_findings({'analysis_logic':'evidence-led','event_timeline':[{'time_utc':'2026-10-28T13:15:55+00:00','time_pht':'2026-10-28T21:15:55+08:00','kind':'Remote-interactive logon','host':'LAB-PC','account':'LabUser'}]})
        values=self.app.event_lab_tree.item('0','values');self.assertIn('2026-10-28T13:15:55+00:00',values);self.assertIn('LAB-PC',values)
    def test_minimum_lab_controls_remain_on_screen(self):
        self.app.geometry('1160x760');self.app.show('Evidence lab');self.app.update()
        self.assertTrue(self.app.lab_tabs.winfo_ismapped())
        bottom=self.app.lab_tabs.winfo_rooty()+self.app.lab_tabs.winfo_height()
        self.assertLessEqual(bottom,self.app.winfo_rooty()+self.app.winfo_height())
