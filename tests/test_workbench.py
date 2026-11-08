"""Synthetic regression fixtures: no client data, captures or malware binaries."""
from __future__ import annotations
import csv
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from test_subject_007.case import Case
from test_subject_007.engine import Settings, run_plugin, plugin_arguments
from test_subject_007.live import FileCursor, LiveFiles
from test_subject_007.profiles import resolve, default_jobs
from test_subject_007.results import index_csv
from test_subject_007.summary import build_summary, observables
from test_subject_007.contextual import contextual_matches
from test_subject_007.reports import export_bundle
from test_subject_007.util import atomic_json


class LiveTests(unittest.TestCase):
    def test_incremental_reads_do_not_repeat_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';path.write_bytes(b'first\rsecond\n')
            cursor=FileCursor(path)
            self.assertEqual(cursor.read(),'first\rsecond\n');self.assertEqual(cursor.read(),'')
            with path.open('ab') as stream:stream.write(b'third')
            self.assertEqual(cursor.read(),'third')

    def test_partial_unicode_sequence_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';path.write_bytes(b'\xe2\x82')
            cursor=FileCursor(path);self.assertEqual(cursor.read(),'')
            with path.open('ab') as out:out.write(b'\xac')
            self.assertEqual(cursor.read(final=True),'\u20ac')

    def test_progress_cr_and_all_streams_and_final_chunk(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[]
            (root/'stderr.log').write_bytes(b'\rProgress: 15.11 Scanning layer\rProgress: 64.75 Scanning layer\r')
            (root/'stdout.csv').write_text('TreeDepth,PID\n0,4\n')
            (root/'volatility.log').write_text('ENGINE-MARKER\n')
            live=LiveFiles(root,'run','test.Plugin',lambda a,b:events.append((a,b)))
            state=live.poll();self.assertEqual(state['percent'],64.75)
            self.assertEqual({e[1]['source'] for e in events},{'stderr','stdout','engine'})
            self.assertTrue(all('\r' not in e[1]['text'] for e in events))
            before=len(events);live.poll();self.assertEqual(len(events),before)
            (root/'stdout.csv').write_text('x'*150000)
            live.poll(final=True)
            self.assertFalse(live.files['stdout'].pending)

    def test_truncated_log_can_be_read_again(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';path.write_text('old-content');cursor=FileCursor(path);cursor.read()
            path.write_text('new');self.assertEqual(cursor.read(),'new')

    def test_live_events_arrive_before_subprocess_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/'capture.raw';image.write_bytes(b'synthetic data')
            case=Case.create(root/'cases',image,'Streaming test','Test analyst','Windows')
            events=[]
            try:
                run=run_plugin(case,'test.stream.Plugin',[],Settings(str(root/'symbols'),True,0,False),'synthetic',threading.Event(),
                               lambda name,event:events.append((name,event,time.monotonic())),
                               prefix=[sys.executable,str(Path(__file__).parent/'fake_volworker.py')])
                self.assertEqual(run['status'],'completed')
                logs=[e for e in events if e[0]=='run_log']
                self.assertTrue(logs)
                self.assertLess(logs[0][2],events[-1][2]-.3)
                sources={e[1]['source'] for e in logs};self.assertEqual(sources,{'stderr','stdout','engine'})
                raw=(case.root/'runs'/run['id']/'stderr.log').read_bytes()
                self.assertIn(b'\rProgress',raw)
                self.assertEqual(run['rows'],3)
            finally:case.close()


class ProfileTests(unittest.TestCase):
    def test_catalog_resolution_does_not_invent_missing_plugins(self):
        cat={'plugins':[{'name':'windows.info.Info'},{'name':'windows.malware.malfind.Malfind'}]}
        selected,missing=resolve(cat,'Windows','Malware investigation')
        self.assertEqual(len(selected),2);self.assertIn('windows.filescan',missing)

    def test_linux_profile_does_not_select_windows_plugins(self):
        cat={'plugins':[{'name':'banners.Banners'},{'name':'linux.pslist.PsList'},{'name':'windows.pslist.PsList'}]}
        selected,missing=resolve(cat,'Linux','Malware investigation')
        self.assertEqual([p['name'] for p in selected],['banners.Banners','linux.pslist.PsList'])

    def test_run_key_profile_expands_explicit_keys(self):
        plugin={'name':'windows.registry.printkey.PrintKey','options':[{'name':'key','flag':'--key','kind':'str','required':False}]}
        jobs=default_jobs(plugin,'Persistence investigation','Windows')
        self.assertEqual(len(jobs),4)
        for values in jobs:self.assertEqual(plugin_arguments(plugin,values)[0],'--key')
        self.assertEqual(default_jobs(plugin,'Custom','Windows'),[{}])


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.image=self.root/'capture.raw';self.image.write_bytes(b'SYNTHETIC evidence bytes')
        self.case=Case.create(self.root/'cases',self.image,'Synthetic report','Analyst','Windows')
        self.case.metadata['synthetic_fixture']=True;self.case.save();self.sequence=0
    def tearDown(self):self.case.close();self.temp.cleanup()
    def add(self,plugin,records,args=None,status='completed'):
        self.sequence+=1;runid=f'fixture-{self.sequence:03d}';folder=self.case.root/'runs'/runid;folder.mkdir()
        columns=['TreeDepth']+list(dict.fromkeys(k for row in records for k in row))
        with (folder/'stdout.csv').open('w',newline='',encoding='utf-8') as out:
            writer=csv.writer(out,escapechar='\\');writer.writerow(columns)
            for row in records:writer.writerow(['0']+[row.get(k,'') for k in columns[1:]])
        count,columns,error=index_csv(folder/'stdout.csv',folder/'results.sqlite')
        self.assertFalse(error)
        run={'id':runid,'plugin':plugin,'arguments':args or [],'status':status,'rows':count,'columns':columns,
             'started_utc':f'2026-01-01T12:00:{self.sequence:02d}+00:00','error':'','index_error':'','offline':True}
        atomic_json(folder/'run.json',run);return run
    def test_startup_finding_includes_specific_pid_and_references(self):
        path=r'C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\document.exe'
        self.add('windows.pslist.PsList',[{'PID':'600','PPID':'400','ImageFileName':'document.exe','CreateTime':'2026-01-01 01:00:00 UTC'}])
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'document.exe','Args':'"'+path+'"'}])
        model=build_summary(self.case);f=next(x for x in model['findings'] if x['category']=='Persistence')
        self.assertEqual(f['pid'],600);self.assertEqual(f['observation'],path)
        self.assertGreaterEqual(len(f['references']),2);self.assertIn('unconfirmed',f['confidence'])
    def test_document_argument_in_startup_is_not_executable_finding(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'reader.exe','Args':r'"C:\Program Files\Reader\reader.exe" "C:\Users\Example\Start Menu\Programs\Startup\other.exe"'}])
        self.assertFalse(build_summary(self.case)['findings'])
    def test_unnamed_module_range_does_not_become_identified_module(self):
        self.add('windows.dlllist.DllList', [{'PID':'600','Base':'0x1000','Size':'0x1000','Path':'-'}])
        self.add('windows.malware.malfind.Malfind', [{'PID':'600','Process':'example.exe','Start VPN':'0x2000','End VPN':'0x20ff','Disasm':'0x2000: jmp 0x1500'}])
        model=build_summary(self.case)
        region=model['malfind_regions'][0]
        self.assertEqual(region['target_module'], '')
        self.assertTrue(region['target_reference'])
        self.assertIn('identity is unresolved', region['context'])

    def test_java_reference_is_reviewed_without_claiming_malware(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'java.exe','Args':r'"C:\Runtime\java.exe" -jar C:\App\business.jar'}])
        model=build_summary(self.case)
        self.assertEqual(model['actionable_count'],0)
        self.assertEqual(model['script_match_count'],1)
        self.assertEqual(model['script_references'][0]['kind'],'Interpreter process/command')
    def test_implausible_process_is_not_counted_as_plausible(self):
        self.add('windows.pslist.PsList',[{'PID':'4','PPID':'0','ImageFileName':'System','Threads':'100'},
                                        {'PID':'234810651320712','PPID':'0','ImageFileName':'','Threads':'2500453712'}])
        model=build_summary(self.case)
        self.assertEqual(model['excluded_pslist_rows'],1);self.assertEqual(model['plausible_process_objects'],1)
        self.assertEqual(model['records_latest'],2);self.assertEqual(len(model['quality_flags']),1)
        self.assertIn('QUALITY',model['assessment'])
    def test_two_registry_queries_are_not_collapsed(self):
        self.add('windows.registry.printkey.PrintKey',[{'Key':'Run'}],['--key','Software\\Run'])
        self.add('windows.registry.printkey.PrintKey',[{'Key':'RunOnce'}],['--key','Software\\RunOnce'])
        self.assertEqual(len(build_summary(self.case)['latest']),2)
    def test_failed_latest_same_options_replaces_previous_success(self):
        self.add('windows.pslist.PsList',[{'PID':'4','ImageFileName':'System'}])
        self.add('windows.pslist.PsList',[],status='failed')
        model=build_summary(self.case);self.assertEqual(model['plausible_process_objects'],0)
    def test_malfind_jump_maps_within_same_pid_only(self):
        self.add('windows.malware.malfind.Malfind',[{'PID':'600','Process':'example.exe','Start VPN':'0x10000','End VPN':'0x10fff','Protection':'PAGE_EXECUTE_READWRITE','Disasm':'0x10000: jmp 0x70001000'}])
        self.add('windows.dlllist.DllList',[{'PID':'600','Base':'0x70000000','Size':'0x20000','Path':r'C:\Security\hook.dll','Name':'hook.dll'}])
        model=build_summary(self.case)
        self.assertEqual(model['malfind_regions'][0]['target_module'],r'C:\Security\hook.dll')
        self.assertEqual(model['findings'][0]['priority'],'Review')
    def test_different_pid_module_is_not_correlated(self):
        self.add('windows.malware.malfind.Malfind',[{'PID':'600','Process':'example.exe','Start VPN':'0x10000','Disasm':'0x10000: jmp 0x70001000'}])
        self.add('windows.dlllist.DllList',[{'PID':'800','Base':'0x70000000','Size':'0x20000','Path':r'C:\Security\hook.dll'}])
        model=build_summary(self.case);self.assertEqual(model['malfind_regions'][0]['target_module'],'')
    def test_report_bundle_contains_complete_finding_sidecars(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'java.exe','Args':'java -jar sample.jar <script>alert(1)</script>'}])
        self.case.metadata['investigation_terms']=['sample.jar']
        result=export_bundle(self.case,self.root/'reports')
        for key in ('findings','quality','regions','exclusions','finding_json','html','pdf'):
            self.assertTrue(Path(result['paths'][key]).is_file())
        html=Path(result['paths']['html']).read_text()
        self.assertIn('Specific findings',html);self.assertIn('F-001',html)
        self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)
        values=json.loads(Path(result['paths']['finding_json']).read_text());self.assertTrue(values[0]['references'])
    def test_case_terms_are_searched_but_not_labeled_malware(self):
        self.case.metadata['investigation_terms']=['sample.jar']
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'java.exe','Args':'java -jar sample.jar'}])
        model=build_summary(self.case)
        self.assertTrue(any(f['category']=='Analyst search' for f in model['findings']))
    def test_unavailable_profile_plugins_are_in_scope_warning(self):
        self.case.metadata['profile_missing']=['windows.filescan']
        self.add('windows.cmdline.CmdLine',[{'PID':'600','Process':'example.exe','Args':'example.exe'}])
        model=build_summary(self.case);self.assertEqual(model['assessment'],'PARTIAL PROFILE COVERAGE')


class ContextTests(unittest.TestCase):
    def test_version_path_is_excluded_not_network_ioc(self):
        found,excluded=contextual_matches({'Path':r'C:\Example\Component\1.2.0.3\module.dll'},'windows.dlllist.DllList',observables)
        self.assertFalse(found);self.assertEqual(excluded[0]['value'],'1.2.0.3')
    def test_framework_path_is_not_domain(self):
        found,excluded=contextual_matches({'Path':r'C:\Windows\Microsoft.NET\Framework\clr.dll'},'windows.dlllist.DllList',observables)
        self.assertFalse(found);self.assertEqual(excluded[0]['value'],'microsoft.net')
    def test_unc_is_not_proof_of_network_session(self):
        found,excluded=contextual_matches({'Args':r'excel.exe "\\192.0.2.7\share\sample.xlsx"'},'windows.cmdline.CmdLine',observables)
        self.assertEqual(found[0][0],'Network share address');self.assertIn('not proof',found[0][2])
    def test_pdb_id_and_argument_are_not_computed_hashes(self):
        value='a'*40
        found,_=contextual_matches({'Args':'browser.exe /pfhostedapp:'+value},'windows.cmdline.CmdLine',observables)
        self.assertEqual(found[0][0],'Identifier candidate')
        found,_=contextual_matches({'Value':'file:///symbols/ntkrnlmp.pdb/'+'b'*32+'-1.json.xz'},'windows.info.Info',observables)
        self.assertEqual(found[0][0],'Symbol identifier')
    def test_network_field_retains_endpoint(self):
        found,_=contextual_matches({'ForeignAddr':'198.51.100.7'},'windows.netscan.NetScan',observables)
        self.assertEqual(found[0][0],'Network endpoint')
