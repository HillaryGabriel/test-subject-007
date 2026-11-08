"""Regression tests for the goal-first workflow and targeted evidence labels."""
import csv
import os
from pathlib import Path
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch
from test_subject_007.case import Case
from test_subject_007.gui import App
from test_subject_007.profiles import GOALS, WIN, LINUX, REMOTE, default_jobs, resolve, goal_details
from test_subject_007.targeted import token_match, remote_matches, network_context
from test_subject_007.results import index_csv
from test_subject_007.summary import build_summary
from test_subject_007.util import atomic_json


def synthetic_catalog():
    candidates={p.split('|')[0] for values in WIN.values() for p in values}
    plugins=[]
    for candidate in sorted(candidates):
        name=candidate if candidate.rsplit('.',1)[-1][:1].isupper() else candidate+'.Fixture'
        options=[{'name':'key','flag':'--key','kind':'str','required':False}] if '.printkey.' in name else []
        plugins.append({'name':name,'description':'SYNTHETIC test entry, not engine discovery.','options':options})
    return {'version':'synthetic','plugins':plugins,'unavailable':[]}


class TargetedUnitTests(unittest.TestCase):
    def test_every_goal_has_windows_and_linux_plan(self):
        self.assertEqual(len(GOALS),9)
        for g in GOALS:
            self.assertIn(g['profile'],WIN);self.assertIn(g['profile'],LINUX)
            self.assertTrue(g['limit']);self.assertTrue(g['question'])
    def test_no_credentials_or_automatic_bulk_dump(self):
        for family in (WIN,LINUX):
            for plugins in family.values():
                self.assertFalse(any(x in p for p in plugins for x in ('hashdump','cachedump','lsadump','dumpfiles')))
    def test_remote_registry_queries_are_explicit(self):
        jobs=default_jobs({'name':'windows.registry.printkey.PrintKey'},REMOTE,'Windows')
        self.assertEqual(len(jobs),5)
        self.assertTrue(all(set(j)=={'key'} and j['key'] for j in jobs))
    def test_linux_remote_does_not_select_windows(self):
        cat={'plugins':[{'name':'linux.sockstat.Sockstat'},{'name':'windows.netscan.NetScan'}]}
        chosen,missing=resolve(cat,'Linux',REMOTE)
        self.assertEqual([p['name'] for p in chosen],['linux.sockstat.Sockstat']);self.assertTrue(missing)
    def test_exact_ip_no_prefix_false_positive(self):
        self.assertTrue(token_match('192.0.2.1',{'ForeignAddr':'192.0.2.1'}))
        self.assertFalse(token_match('192.0.2.1',{'ForeignAddr':'192.0.2.100'}))
    def test_ip_in_url_with_port(self):
        self.assertTrue(token_match('192.0.2.1',{'Args':'curl https://192.0.2.1:8443/test'}))
        self.assertFalse(token_match('192.0.2.1',{'Args':'curl https://192.0.2.100:8443/test'}))
    def test_bracketed_ipv6_with_port(self):
        self.assertTrue(token_match('2001:db8::1',{'Args':'https://[2001:db8::1]:443/test'}))
        self.assertFalse(token_match('2001:db8::1',{'Args':'https://[2001:db8::10]:443/test'}))
    def test_linux_psaux_uses_args_and_comm(self):
        self.assertEqual(remote_matches('linux.psaux.PsAux',{'COMM':'sshd','ARGS':'/usr/sbin/sshd -D'}),['SSH server'])
        self.assertEqual(remote_matches('linux.psaux.PsAux',{'COMM':'wrapper','ARGS':'/usr/bin/rustdesk --service'}),['RustDesk'])
        self.assertEqual(remote_matches('linux.psaux.PsAux',{'COMM':'cat','ARGS':'/usr/bin/cat /tmp/rustdesk'}),[])
    def test_linux_sockstat_column_names(self):
        r={'PID':'88','Process Name':'sshd','Source Addr':'::','Source Port':'22','Destination Addr':'::','Destination Port':'0','Proto':'TCP','State':'LISTEN'}
        got=network_context([{'plugin':'linux.sockstat.Sockstat','run_id':'x','row_id':1,'record':r}])[0]
        self.assertEqual(got['owner'],'sshd');self.assertEqual(got['local_address'],'::')
        self.assertEqual(got['local_port'],'22');self.assertIn('SSH',got['port_context'])
        self.assertEqual(got['record'],r)
    def test_linux_endpoint_label(self):
        from test_subject_007.contextual import contextual_matches
        def extractor(text):
            return [('IP address',text,'test')]
        got,excluded=contextual_matches({'Destination Addr':'192.0.2.8'},'linux.sockstat.Sockstat',extractor)
        self.assertEqual(got[0][0],'Network endpoint');self.assertEqual(excluded,[])
    def test_path_version_not_indicator(self):
        self.assertFalse(token_match('1.2.0.3',{'Path':r'C:\App\1.2.0.3\file.dll'}))
    def test_share_reference_still_searchable(self):
        self.assertTrue(token_match('192.0.2.1',{'Args':r'excel "\\192.0.2.1\work\report.xlsx"'}))
    def test_domain_boundaries(self):
        self.assertTrue(token_match('example.org',{'Url':'https://example.org/test'}))
        self.assertFalse(token_match('example.org',{'Url':'https://notexample.org/test'}))
    def test_hash_and_literal_terms(self):
        self.assertTrue(token_match('a'*64,{'Value':'hash='+'a'*64}))
        self.assertFalse(token_match('a'*64,{'Value':'a'*65}))
        self.assertTrue(token_match('Retrive',{'Name':'RetriveExample.vbs'}))
    def test_remote_executable_only_not_document_argument(self):
        self.assertEqual(remote_matches('windows.cmdline.CmdLine',{'Process':'anydesk.exe','Args':'"C:\\Tools\\AnyDesk.exe"'}),['AnyDesk'])
        self.assertEqual(remote_matches('windows.cmdline.CmdLine',{'Args':r'notepad.exe "C:\Tools\anydesk.exe"'}),[])
        self.assertEqual(remote_matches('windows.dlllist.DllList',{'Path':r'C:\anydesk.exe'}),[])
    def test_service_host_is_context_not_connection(self):
        self.assertEqual(remote_matches('windows.cmdline.CmdLine',{'Process':'svchost.exe','Args':'svchost.exe -k NetworkService -s TermService'}),['RDP service host'])
    def test_network_port_context_keeps_original(self):
        raw={'PID':'32','LocalAddr':'0.0.0.0','LocalPort':'3389','ForeignAddr':'0.0.0.0','ForeignPort':'0','State':'LISTENING'}
        got=network_context([{'plugin':'windows.netscan.NetScan','run_id':'x','row_id':1,'record':raw}])[0]
        self.assertIn('conventional',got['port_context']);self.assertEqual(got['record'],raw)


class TargetedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        p=self.root/'synthetic.raw';p.write_bytes(b'NOT A MEMORY CAPTURE')
        self.case=Case.create(self.root/'cases',p,'SYNTHETIC','Tester','Windows');self.n=0
    def tearDown(self):self.case.close();self.tmp.cleanup()
    def add(self,plugin,rows):
        self.n+=1;rid=f'synthetic-{self.n:02d}';folder=self.case.root/'runs'/rid;folder.mkdir()
        fields=['TreeDepth']+list(dict.fromkeys(k for row in rows for k in row))
        with (folder/'stdout.csv').open('w',encoding='utf-8',newline='') as f:
            w=csv.writer(f,escapechar='\\');w.writerow(fields)
            for row in rows:w.writerow(['0']+[row.get(k,'') for k in fields[1:]])
        n,cols,e=index_csv(folder/'stdout.csv',folder/'results.sqlite');self.assertFalse(e)
        atomic_json(folder/'run.json',{'id':rid,'plugin':plugin,'status':'completed','arguments':[], 'rows':n,'started_utc':'2026-01-01T00:00:00+00:00'})
    def test_remote_tool_and_socket_reference_not_malware(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'42','Process':'anydesk.exe','Args':'anydesk.exe --service'}])
        self.add('windows.netscan.NetScan',[{'PID':'42','Owner':'anydesk.exe','LocalAddr':'192.0.2.10','LocalPort':'50123','ForeignAddr':'198.51.100.10','ForeignPort':'443','State':'ESTABLISHED'}])
        model=build_summary(self.case);f=next(f for f in model['findings'] if f['category']=='Remote access')
        self.assertEqual(f['priority'],'Review');self.assertEqual(len(f['references']),2)
        self.assertIn('not proof',f['interpretation']);self.assertEqual(len(model['network_context']),1)
    def test_ip_match_in_network_only_output_is_found(self):
        self.case.metadata['investigation_terms']=['198.51.100.10']
        self.add('windows.netscan.NetScan',[{'PID':'42','ForeignAddr':'198.51.100.10','ForeignPort':'443'}])
        model=build_summary(self.case);self.assertEqual(len(model['keyword_matches']),1)
        f=next(f for f in model['findings'] if f['category']=='Analyst search')
        self.assertIn('ForeignAddr',f['observation'])
    def test_powershell_vbs_and_java_references(self):
        self.add('windows.filescan.FileScan',[{'Name':r'\Device\Disk\Temp\RetriveDemo.vbs'},{'Name':r'\Scripts\business.ps1'}])
        self.add('windows.cmdline.CmdLine',[{'PID':'42','Process':'java.exe','Args':'java.exe -jar business.jar'}])
        model=build_summary(self.case);self.assertEqual(model['script_match_count'],3)
        self.assertTrue(all(f['priority']=='Review' for f in model['findings']))
    def test_rdp_port_is_informational(self):
        self.add('windows.netscan.NetScan',[{'PID':'42','LocalAddr':'0.0.0.0','LocalPort':'3389','ForeignAddr':'0.0.0.0','ForeignPort':'0','State':'LISTENING'}])
        model=build_summary(self.case);f=next(f for f in model['findings'] if f['category']=='Remote-service ports')
        self.assertEqual(f['priority'],'Informational');self.assertIn('not proof',f['interpretation'])
    def test_goal_metadata_is_preserved(self):
        self.case.metadata['investigation_goal']=goal_details(REMOTE)
        self.assertEqual(build_summary(self.case)['investigation_goal']['title'],'Remote access & RDP')


class GuidedGuiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{'TS007_HOME':str(self.root/'home')});self.env.start()
        try:self.app=App(auto_discover=False);self.app.update()
        except tk.TclError as e:self.env.stop();self.tmp.cleanup();self.skipTest(str(e))
        self.app.catalog=synthetic_catalog();self.app.filter_plugins()
    def tearDown(self):
        if self.app.case:self.app.case.close()
        self.app.destroy();self.env.stop();self.tmp.cleanup()
    def test_guided_is_default_and_nine_goals_exist(self):
        self.assertEqual(self.app.mode_tabs.select(),str(self.app.guided_plan));self.assertEqual(len(self.app.goal_cards),9)
    def test_click_applies_without_running(self):
        with patch.object(self.app,'run_batch') as run:self.app.select_goal(REMOTE)
        run.assert_not_called();self.assertEqual(self.app.profile_applied,REMOTE)
        self.assertTrue(any('.sessions.' in p for p in self.app.checked_plugins))
    def test_missing_case_disables_run(self):
        self.app.select_goal(REMOTE);self.assertEqual(str(self.app.guided_run_button.cget('state')),'disabled')
    def test_manual_checkbox_becomes_custom(self):
        self.app.select_goal(REMOTE);self.app.toggle_plugin(next(iter(self.app.checked_plugins)))
        self.assertEqual(self.app.profile_var.get(),'Custom')
    def test_both_tabs_and_bottom_controls_reachable_at_minimum(self):
        self.app.geometry('1160x760');self.app.show('Analyze');self.app.update()
        self.assertTrue(self.app.guided_run_button.winfo_ismapped())
        bottom=self.app.guided_run_button.winfo_rooty()+self.app.guided_run_button.winfo_height()
        self.assertLessEqual(bottom,self.app.winfo_rooty()+self.app.winfo_height())
        self.app.goal_scroll.canvas.yview_moveto(1);self.app.update()
        self.assertAlmostEqual(self.app.goal_scroll.canvas.yview()[1],1.)
        self.app.open_advanced();self.app.update();self.assertTrue(self.app.plugin_tree.winfo_ismapped())
    def test_export_dialog_many_paths_stays_usable(self):
        from test_subject_007.dialogs import ExportDialog
        d=ExportDialog(self.app,{f'report-{i}':str(self.root/f'file-{i}.txt') for i in range(24)})
        try:
            d.geometry('800x500');d.update()
            self.assertEqual(len(d.path_vars),24)
            self.assertTrue(d.action_footer.winfo_ismapped())
            self.assertLessEqual(d.action_footer.winfo_rooty()+d.action_footer.winfo_height(),d.winfo_rooty()+d.winfo_height())
            d.path_scroll.canvas.yview_moveto(1);d.update()
            self.assertAlmostEqual(d.path_scroll.canvas.yview()[1],1.0)
        finally:d.destroy()
    def test_busy_goal_click_does_not_change_plan(self):
        self.app.select_goal(REMOTE);old=set(self.app.checked_plugins);self.app.busy=True
        self.app.select_goal('Quick triage');self.assertEqual(self.app.checked_plugins,old)
        self.app.busy=False
    def test_case_readiness_and_live_state(self):
        p=self.root/'synthetic.raw';p.write_bytes(b'NO MEMORY')
        self.app.install_case(Case.create(self.root/'cases',p,'Synthetic test','Tester','Windows'))
        self.app.select_goal(REMOTE);self.assertEqual(str(self.app.guided_run_button.cget('state')),'normal')
        self.app.busy=True;self.app.refresh_guided();self.assertEqual(str(self.app.guided_run_button.cget('state')),'disabled')
        self.app.busy=False


class CleanSettingsTests(unittest.TestCase):
    def test_reset_backs_up_preferences_and_preserves_cases(self):
        import json, sys
        from test_subject_007.__main__ import main
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{'TS007_HOME':folder}):
            root=Path(folder)
            (root/'settings.json').write_text('{"offline":false}')
            (root/'recent-locations.json').write_text('{"os":"Windows"}')
            (root/'case.json').write_text('PRESERVE EVIDENCE')
            with patch.object(sys,'argv',['test-subject-007','--fresh-settings','--offline-symbols']),patch('test_subject_007.gui.launch') as launch:
                main()
            launch.assert_called_once_with(None)
            self.assertTrue(json.loads((root/'settings.json').read_text())['offline'])
            self.assertEqual(len(list(root.glob('settings-backup-*.json'))),1)
            self.assertEqual(len(list(root.glob('recent-locations-backup-*.json'))),1)
            self.assertEqual((root/'case.json').read_text(),'PRESERVE EVIDENCE')
    def test_reset_is_optional(self):
        import sys
        from test_subject_007.__main__ import main
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'TS007_HOME':folder}):
            p=Path(folder)/'settings.json';p.write_text('{"offline":true}')
            with patch.object(sys,'argv',['test-subject-007']),patch('test_subject_007.gui.launch'):
                main()
            self.assertEqual(p.read_text(),'{"offline":true}')
            self.assertFalse(list(Path(folder).glob('settings-backup*')))
