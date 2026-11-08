"""Regression tests for diagnostics, path selection, summaries and report delivery."""
from __future__ import annotations
import csv
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from test_subject_007.case import Case
from test_subject_007.diagnostics import diagnose,collect_log
from test_subject_007.engine import Settings,run_plugin
from test_subject_007.paths import user_path,inspect_image,find_dumps
from test_subject_007.reports import export_bundle
from test_subject_007.results import index_csv,query_rows
from test_subject_007.summary import build_summary,observables,get_observables
from test_subject_007.util import atomic_json,hash_file


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.image=self.root/'memory with spaces.raw';self.image.write_bytes(b'SYNTHETIC TEST IMAGE\x00'*100)
        self.case=Case.create(self.root/'cases',self.image,'Repair fixture','Test analyst','Windows')
    def tearDown(self):
        self.case.close();self.temp.cleanup()
    def add_run(self,name='windows.pslist.PsList',status='completed',records=None,run_id='20260101T120000-test',message=''):
        folder=self.case.root/'runs'/run_id;folder.mkdir()
        records=records if records is not None else [{'PID':'4','ImageFileName':'System','Command':'https://example.org/a 198.51.100.12'}]
        columns=['TreeDepth']+list(dict.fromkeys(k for row in records for k in row))
        with (folder/'stdout.csv').open('w',newline='',encoding='utf-8') as out:
            writer=csv.writer(out,escapechar='\\');writer.writerow(columns)
            for row in records:writer.writerow(['0']+[row.get(k,'') for k in columns[1:]])
        if message:(folder/'stdout.csv').write_text(message,encoding='utf-8')
        rows,cols,error=index_csv(folder/'stdout.csv',folder/'results.sqlite')
        (folder/'stderr.log').write_text('Framework diagnostic output',encoding='utf-8')
        run={'id':run_id,'plugin':name,'status':status,'started_utc':run_id[:15],'rows':rows,'columns':cols,'index_error':error,
             'error':'','offline':True,'finished_utc':'2026-01-01T12:00:10Z'}
        atomic_json(folder/'run.json',run)
        return run,folder

    def test_error_stdout_is_not_a_header(self):
        run,folder=self.add_run(status='failed',message='Unsatisfied requirement plugins.Info.kernel.layer_name: required\n')
        columns,rows,total=query_rows(folder/'results.sqlite')
        self.assertEqual(columns,[]);self.assertEqual(rows,[]);self.assertEqual(total,0)
        diagnosis=diagnose(run,folder)
        self.assertEqual(diagnosis['code'],'requirements')
        self.assertIn('plugins.Info.kernel.layer_name',diagnosis['requirements'])
        self.assertTrue(any('offline' in s for s in diagnosis['actions']))

    def test_log_combines_stdout_stderr_and_engine_log(self):
        _,folder=self.add_run()
        (folder/'volatility.log').write_text('ENGINE-LOG-MARKER',encoding='utf-8')
        output=collect_log(folder)
        for expected in ('stdout.csv','stderr.log','volatility.log','ENGINE-LOG-MARKER','example.org'):
            self.assertIn(expected,output)

    def test_file_path_quotes_uri_and_spaces(self):
        self.assertEqual(user_path('"'+str(self.image)+'"'), self.image.resolve(strict=True))
        self.assertEqual(user_path(self.image.as_uri()), self.image.resolve(strict=True))
        self.assertEqual(inspect_image(self.image)['size'],self.image.stat().st_size)

    def test_minidump_rejected_before_kernel_analysis(self):
        path=self.root/'process.dmp';path.write_bytes(b'MDMP'+b'\0'*128)
        with self.assertRaisesRegex(ValueError,'minidump'):inspect_image(path)

    def test_compressed_container_not_silently_treated_as_raw(self):
        path=self.root/'renamed.raw';path.write_bytes(b'PK\x03\x04'+b'x'*100)
        with self.assertRaisesRegex(ValueError,'archive'):inspect_image(path)

    def test_dump_finder_finds_names_and_skips_hidden_folders(self):
        (self.root/'hidden.txt').write_text('not a dump')
        hidden=self.root/'.cache';hidden.mkdir();(hidden/'private.dmp').write_bytes(b'x')
        records,limited=find_dumps([self.root],max_depth=1)
        self.assertIn(str(self.image.resolve(strict=True)), [r['path'] for r in records])
        self.assertNotIn(str(hidden/'private.dmp'),[r['path'] for r in records]);self.assertFalse(limited)

    def test_dump_finder_limit_is_explicit(self):
        for i in range(8):(self.root/f'{i}.dmp').write_bytes(b'x')
        records,limited=find_dumps([self.root],max_results=2)
        self.assertEqual(len(records),2);self.assertTrue(limited)

    def test_observable_extraction_validates_ip_syntax(self):
        data=list(observables('999.1.2.3 198.51.100.2 2001:db8::1 powershell.exe example.org '+('a'*64)))
        values={x[1] for x in data}
        self.assertIn('198.51.100.2',values);self.assertIn('2001:db8::1',values)
        self.assertNotIn('999.1.2.3',values);self.assertNotIn('powershell.exe',values)
        self.assertIn('example.org',values);self.assertIn('a'*64,values)

    def test_latest_attempt_prevents_repeated_run_double_counting(self):
        self.add_run(run_id='20260101T120000-test')
        self.add_run(run_id='20260102T120000-test')
        model=build_summary(self.case)
        self.assertEqual(len(model['runs']),2);self.assertEqual(len(model['latest']),1)
        self.assertEqual(model['records_latest'],1)
        values,_=get_observables(self.case)
        self.assertEqual(next(r['occurrences'] for r in values if r['value']=='198.51.100.12'),1)

    def test_latest_failure_does_not_silently_use_old_success(self):
        self.add_run(run_id='20260101T120000-test')
        self.add_run(run_id='20260102T120000-test',status='failed',message='Unsatisfied requirement plugins.PsList.kernel.symbol_table_name:\n')
        model=build_summary(self.case)
        self.assertEqual(model['complete_latest'],0)
        self.assertEqual(model['assessment'],'ANALYSIS INCOMPLETE')
        self.assertEqual(model['observable_total'],0)

    def test_report_bundle_all_formats_have_real_paths_and_hashes(self):
        self.add_run()
        before=hash_file(self.image)
        bundle=export_bundle(self.case,self.root/'Chosen report directory')
        for kind in ('pdf','html','csv','observables'):
            self.assertTrue(Path(bundle['paths'][kind]).is_file())
        self.assertTrue(Path(bundle['paths']['pdf']).read_bytes().startswith(b'%PDF-'))
        self.assertIn('<svg',Path(bundle['paths']['html']).read_text())
        self.assertFalse((Path(bundle['folder'])/'INCOMPLETE.txt').exists())
        self.assertEqual(self.case.metadata['last_exports'],bundle['paths'])
        self.assertEqual(hash_file(self.image),before)
        for line in (Path(bundle['folder'])/'SHA256SUMS.txt').read_text().splitlines():
            digest,name=line.split('  ',1)
            self.assertEqual(hash_file(Path(bundle['folder'])/name),digest)

    def test_failure_report_csv_is_explicit_diagnostic_not_fake_finding(self):
        self.add_run(name='windows.info.Info',status='failed',message='Unsatisfied requirement plugins.Info.kernel.symbol_table_name: missing\n')
        bundle=export_bundle(self.case,self.root/'reports')
        with open(bundle['paths']['csv'],newline='',encoding='utf-8') as stream:
            rows=list(csv.DictReader(stream))
        self.assertEqual(rows[0]['Record type'],'run_status');self.assertEqual(rows[0]['Run status'],'failed')
        self.assertIn('ANALYSIS INCOMPLETE',Path(bundle['paths']['html']).read_text())
        self.assertIn('plugins.Info.kernel.symbol_table_name',Path(bundle['paths']['html']).read_text())

    def test_bundle_formula_escape_and_html_injection_protection(self):
        self.add_run(records=[{'PID':'1','Command':'=HYPERLINK("bad") <script>alert(1)</script>'}])
        bundle=export_bundle(self.case,self.root/'reports')
        with open(bundle['paths']['csv'],newline='',encoding='utf-8') as stream:
            row=next(csv.DictReader(stream))
        self.assertTrue(row['Data: Command'].startswith("'="))
        self.assertNotIn('<script>',Path(bundle['paths']['html']).read_text())

    def test_export_failures_do_not_pretend_to_be_complete(self):
        self.add_run()
        with patch('test_subject_007.reports.write_pdf',side_effect=RuntimeError('PDF dependency failure')):
            with self.assertRaisesRegex(RuntimeError,'Partial files'):
                export_bundle(self.case,self.root/'reports')
        self.assertNotIn('last_exports',self.case.metadata)
        self.assertEqual(len(list((self.root/'reports').glob('*/INCOMPLETE.txt'))),1)

    def test_all_export_formats_protect_the_evidence_location(self):
        self.add_run()
        with self.assertRaises(ValueError):export_bundle(self.case,self.case.root/'runs')

    def test_export_paths_survive_reopening_case(self):
        self.add_run();bundle=export_bundle(self.case,self.root/'reports')
        root=self.case.root;self.case.close();self.case=Case.open(root)
        self.assertEqual(self.case.metadata['last_exports'],bundle['paths'])

    def test_repeated_exports_never_overwrite_prior_report(self):
        self.add_run()
        first=export_bundle(self.case,self.root/'reports');second=export_bundle(self.case,self.root/'reports')
        self.assertNotEqual(first['folder'],second['folder'])
        self.assertTrue(Path(first['paths']['pdf']).is_file())

    def test_legacy_export_destination_can_be_recovered_from_audit(self):
        from test_subject_007.reports import recover_last_exports
        destination=self.root/'old reports'/'case.html'
        self.case.audit('report_exported',{'destination':str(destination)})
        self.assertEqual(recover_last_exports(self.case),{'html':str(destination)})

    def test_integrity_mismatch_overrides_successful_run_assessment(self):
        self.add_run()
        self.case.metadata['verification']='mismatch';self.case.save()
        model=build_summary(self.case)
        self.assertEqual(model['assessment'],'INTEGRITY WARNING')
        self.assertIn('Do not rely',model['summary'])


if __name__=='__main__':unittest.main()
