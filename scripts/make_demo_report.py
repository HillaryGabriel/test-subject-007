#!/usr/bin/env python3
"""Generate clearly labeled SYNTHETIC reports; does not invoke Volatility."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_subject_007.case import Case
from test_subject_007.results import index_csv
from test_subject_007.reports import export_bundle
from test_subject_007.util import atomic_json
from test_subject_007.profiles import goal_details, REMOTE
from test_subject_007.eventlogs import import_event_file
from test_subject_007.binaries import import_binary


def make_demo(output: Path):
    output=output.expanduser().resolve();output.mkdir(parents=True,exist_ok=True)
    # Synthetic case records are separate from the application's source.
    work=Path(tempfile.mkdtemp(prefix='ts007-synthetic-'))
    image=work/'SYNTHETIC-NOT-A-MEMORY-CAPTURE.raw'
    image.write_bytes(b'SYNTHETIC DEMONSTRATION ONLY\n'*100)
    case=Case.create(work/'cases',image,'SYNTHETIC / EVIDENCE REVIEW','Demonstration analyst','Windows')
    case.metadata.update(synthetic_fixture=True,investigation_profile=REMOTE,investigation_goal=goal_details(REMOTE),investigation_terms=[])
    case.save()
    index=0
    def add(plugin,records):
        nonlocal index
        index+=1;runid=f'SYNTHETIC-{index:02d}';folder=case.root/'runs'/runid;folder.mkdir()
        columns=['TreeDepth']+list(dict.fromkeys(k for row in records for k in row))
        with (folder/'stdout.csv').open('w',encoding='utf-8',newline='') as out:
            w=csv.writer(out,escapechar='\\');w.writerow(columns)
            for row in records:w.writerow(['0']+[row.get(k,'') for k in columns[1:]])
        n,cols,err=index_csv(folder/'stdout.csv',folder/'results.sqlite')
        atomic_json(folder/'run.json',{'id':runid,'plugin':plugin,'arguments':[],'status':'completed','rows':n,'columns':cols,
             'started_utc':f'2026-01-01T12:00:{index:02d}+00:00','error':'','index_error':err,'offline':True,
             'command_argv':['SYNTHETIC FIXTURE - no engine executed'], 'output_files':[]})
    path=r'C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\document.exe'
    add('windows.info.Info',[{'Variable':'SystemTime','Value':'2026-01-01 11:00:00+00:00'},
                            {'Variable':'NtSystemRoot','Value':r'C:\Windows'},
                            {'Variable':'Symbols','Value':'file:///synthetic/symbols/ntkrnlmp.pdb/'+'b'*32+'-1.json.xz'}])
    processes=[{'PID':'4','PPID':'0','ImageFileName':'System','Threads':'50','CreateTime':'2026-01-01 08:00:00 UTC','Offset(V)':'0x100'},
               {'PID':'400','PPID':'4','ImageFileName':'explorer.exe','Threads':'12','CreateTime':'2026-01-01 09:00:00 UTC','Offset(V)':'0x200'},
               {'PID':'600','PPID':'400','ImageFileName':'document.exe','Threads':'3','CreateTime':'2026-01-01 09:01:00 UTC','Offset(V)':'0x300'},
               {'PID':'800','PPID':'400','ImageFileName':'java.exe','Threads':'20','CreateTime':'2026-01-01 09:02:00 UTC','Offset(V)':'0x400'},
               {'PID':'900','PPID':'400','ImageFileName':'powershell.exe','Threads':'6','CreateTime':'2026-01-01 09:03:00 UTC','Offset(V)':'0x500'},
               {'PID':'999999999999','PPID':'0','ImageFileName':'','Threads':'2500000000','CreateTime':'1601-01-01 00:00:00 UTC','Offset(V)':'0x600'}]
    add('windows.pslist.PsList',processes)
    add('windows.cmdline.CmdLine',[{'PID':'600','Process':'document.exe','Args':'"'+path+'"'},
        {'PID':'800','Process':'java.exe','Args':r'"C:\BusinessApp\java.exe" -jar C:\BusinessApp\sample.jar'},
        {'PID':'900','Process':'powershell.exe','Args':'powershell.exe -EncodedCommand U1lOVEhFVElD'},
        {'PID':'1200','Process':'AnyDesk.exe','Args':r'"C:\Program Files\AnyDesk\AnyDesk.exe" --service'},
        {'PID':'1600','Process':'lsass.exe','Args':r'C:\Users\Public\lsass.exe'},
        {'PID':'1000','Process':'excel.exe','Args':r'excel.exe "\\192.0.2.7\share\example.xlsx"'}])
    add('windows.dlllist.DllList',[{'PID':'600','Process':'document.exe','Base':'0x70000000','Size':'0x20000','Name':'hook.dll','Path':r'C:\Program Files\ExampleSecurity\hook.dll'},
        {'PID':'1000','Process':'browser.exe','Base':'0x71000000','Size':'0x1000','Name':'component.dll','Path':r'C:\Users\Example\Browser\Component\1.2.0.3\component.dll'},
        {'PID':'800','Process':'java.exe','Base':'0x72000000','Size':'0x1000','Name':'clr.dll','Path':r'C:\Windows\Microsoft.NET\Framework\clr.dll'}])
    add('windows.malware.malfind.Malfind',[{'PID':'600','Process':'document.exe','Start VPN':'0x10000','End VPN':'0x10fff','Protection':'PAGE_EXECUTE_READWRITE','Disasm':'0x10000: jmp 0x70001000','Hexdump':'e9 fb 0f ff 6f'},
        {'PID':'1100','Process':'runtime.exe','Start VPN':'0x20000','End VPN':'0x20fff','Protection':'PAGE_EXECUTE_READWRITE','Disasm':'0x20000: add byte ptr [rax], al','Hexdump':'00 00 00 00 00 00 00 00'}])
    add('windows.netscan.NetScan',[{'PID':'1000','Owner':'browser.exe','Proto':'TCPv4','LocalAddr':'192.0.2.10','LocalPort':'50000','ForeignAddr':'198.51.100.20','ForeignPort':'443','State':'ESTABLISHED','Created':'2026-01-01 09:30:00.000000 UTC'},
        {'PID':'1200','Owner':'AnyDesk.exe','Proto':'TCPv4','LocalAddr':'192.0.2.10','LocalPort':'50100','ForeignAddr':'198.51.100.30','ForeignPort':'443','State':'ESTABLISHED','Created':'N/A'},
        {'PID':'1400','Owner':'svchost.exe','Proto':'TCPv4','LocalAddr':'192.0.2.10','LocalPort':'3389','ForeignAddr':'192.0.2.20','ForeignPort':'50123','State':'ESTABLISHED','Created':'2026-01-01 09:15:00.000000 UTC'}])
    add('windows.filescan.FileScan',[{'Offset':'0x999','Name':r'\Device\HarddiskVolume1\BusinessApp\sample.jar'}])
    add('windows.envars.Envars',[{'PID':str(i+2000),'Process':'svchost.exe','Variable':'PATHEXT','Value':'.EXE;.CMD;.VBS;.JS;.WSF'} for i in range(113)])
    add('windows.svcscan.SvcScan',[{'Name':'vmicvmsession','Display':'Hyper-V PowerShell Direct Service','State':'SERVICE_STOPPED','Binary':'N/A','Binary (Registry)':r'C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted'}])
    # A preserved synthetic byte fixture, not a program; SHA-256 is genuinely computed.
    sample=work/'SYNTHETIC-NONEXECUTABLE-FILE.bin';sample.write_bytes(b'SYNTHETIC INERT BYTES - NOT A MALWARE SAMPLE\n')
    import_binary(case,sample,600,path)
    events=work/'SYNTHETIC-Security.xml'
    records=[]
    for record,eid,typ,time in [('1',4624,'10','2026-01-01T09:15:30Z'),('2',4779,'','2026-01-01T09:45:00Z')]:
        records.append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>'+str(eid)+'</EventID><TimeCreated SystemTime="'+time+'"/><EventRecordID>'+record+'</EventRecordID><Channel>Security</Channel><Computer>SYNTHETIC-LAB-PC</Computer></System><EventData><Data Name="TargetUserName">LabUser</Data><Data Name="LogonType">'+typ+'</Data><Data Name="IpAddress">192.0.2.20</Data><Data Name="SessionName">RDP-Tcp#1</Data></EventData></Event>')
    events.write_text('<Events>'+''.join(records)+'</Events>',encoding='utf-8')
    import_event_file(case,events)
    try:
        result=export_bundle(case,output)
        print(json.dumps({'folder':result['folder'],'paths':result['paths'],'case':str(case.root)},indent=2))
        return result,case.root
    finally:case.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();make_demo(args.output)
