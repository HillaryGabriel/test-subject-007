"""Import supplied EVTX/XML. Does not carve RAM or invent session times."""
from __future__ import annotations
from pathlib import Path
import shutil
from .chronology import timestamp
from .supplemental import copy_source,finish_import,load_supplements
from .util import Cancelled

MAX_RECORDS=200000


def local(tag):return tag.rsplit('}',1)[-1]


def event_record(element, reference, origin):
    system=next((e for e in element if local(e.tag)=='System'),None)
    if system is None:return None
    fields={local(e.tag):(e.text or '').strip() for e in system}
    provider=next((e.get('Name','') for e in system if local(e.tag)=='Provider'),'')
    raw_time=next((e.get('SystemTime','') for e in system if local(e.tag)=='TimeCreated'),'')
    try:eid=int(fields.get('EventID',''))
    except ValueError:return None
    data={}
    for node in element:
        if local(node.tag) not in ('EventData','UserData'):continue
        for leaf in node.iter():
            if len(leaf)==0:
                key=leaf.get('Name') or local(leaf.tag)
                data[key]=(leaf.text or '').strip()
    channel=fields.get('Channel','');name=provider.casefold();kind='';meaning='';category='Authentication'
    account=data.get('TargetUserName',data.get('User',data.get('Param1',data.get('AccountName',''))))
    domain=data.get('TargetDomainName',data.get('Param2',data.get('AccountDomain','')))
    address=data.get('IpAddress',data.get('Address',data.get('Param3',data.get('ClientAddress',''))))
    session=data.get('SessionID',data.get('SessionId',data.get('SessionName','')))
    logon_type=data.get('LogonType','')
    if name=='microsoft-windows-security-auditing' and channel.casefold()=='security':
        if eid==4624:
            kind={'10':'Remote-interactive logon','3':'Network logon','2':'Local interactive logon','7':'Unlock'}.get(logon_type,'Successful logon (type '+(logon_type or 'unknown')+')')
            meaning='Recorded logon type '+(logon_type or 'not supplied')+'; authorization and human operator are not established.'
        elif eid==4625:kind='Failed logon';meaning='Attempt failed; not a successful remote session.'
        elif eid in (4634,4647):kind='Logoff recorded';meaning='Logoff event; relate using host and logon ID, not account name alone.'
        elif eid in (4778,4779):
            kind='Session reconnected' if eid==4778 else 'Session disconnected'
            meaning='Window-station event; inspect session name and host. No automatic cross-host/session pairing.'
        elif eid==4776:
            kind='NTLM credential validation';meaning='Credential validation on the reporting host, not proof of a desktop logon; no logon-type field.'
    elif name=='microsoft-windows-terminalservices-remoteconnectionmanager' and eid==1149:
        if 'remoteconnectionmanager' not in channel.casefold():return None
        kind='RDP authentication event';meaning='RemoteConnectionManager authentication record; does not alone establish desktop logon, session duration or authorization.'
    elif name=='microsoft-windows-terminalservices-localsessionmanager' and eid in (21,22,23,24,25):
        if 'localsessionmanager' not in channel.casefold():return None
        kind={21:'Session logon',22:'Session shell start',23:'Session logoff',24:'Session disconnect',25:'Session reconnect'}[eid]
        kind += ' (local)' if address.casefold() in ('local','127.0.0.1','::1') else ' (transport requires context)'
        meaning='LocalSessionManager event. LOCAL is not evidence of remote access. Source address and session/host context must be reviewed.'
    if not kind:return None
    return {**timestamp(raw_time), 'kind':kind,'category':category,'timestamp_field':'System/TimeCreated/@SystemTime',
            'host':fields.get('Computer',''),'channel':channel,'provider':provider,'event_id':eid,
            'record_id':fields.get('EventRecordID',''),'account':account,'domain':domain,'source_address':address,
            'session_id':session,'logon_id':data.get('TargetLogonId',data.get('LogonID','')),
            'logon_type':logon_type,'origin':origin,'interpretation':meaning,'data':data,'reference':reference}


def import_event_file(case,source,origin='External event log (analyst supplied)',cancel=None,emit=lambda *_:None):
    if origin not in ('External event log (analyst supplied)','Memory-recovered event file (analyst supplied)'):
        raise ValueError('Select an explicit event-file provenance.')
    from defusedxml import ElementTree as ET
    folder,meta=copy_source(case,source,'events',cancel)
    path=case.root/meta['case_path'];records=[];total=0;errors=0;limited=False
    try:
        with path.open('rb') as stream:magic=stream.read(8)
        def accept(element):
            nonlocal total
            total+=1
            ref={'import_id':meta['id'],'source_sha256':meta['sha256'],'source_record':total,'case_path':meta['case_path']}
            result=event_record(element,ref,origin)
            if result:records.append(result)
            if total%1000==0:emit('status',f'Reading event records: {total:,}; relevant: {len(records):,}')
        if magic.startswith(b'ElfFile'):
            try:from Evtx.Evtx import Evtx
            except ImportError as exc:raise ValueError('EVTX parser is not installed. Reinstall with analysis extras or import an XML Events export.') from exc
            with Evtx(str(path)) as log:
                for event in log.records():
                    if cancel and cancel.is_set():raise Cancelled('Event import cancelled.')
                    if total+errors>=MAX_RECORDS:limited=True;break
                    try:accept(ET.fromstring(event.xml(),forbid_dtd=True))
                    except Cancelled:raise
                    except Exception:errors+=1
        else:
            for _,element in ET.iterparse(str(path),events=('end',),forbid_dtd=True):
                if local(element.tag)!='Event':continue
                if cancel and cancel.is_set():raise Cancelled('Event import cancelled.')
                if total+errors>=MAX_RECORDS:limited=True;break
                accept(element);element.clear()
        meta.update(origin=origin,records_examined=total+errors,records_parsed=total,relevant_records=len(records),parse_errors=errors,
                    limited=limited,coverage='Partial' if errors or limited else 'Parsed supplied file',
                    limitation='No raw-memory carving, no reconstruction of missing events, no authorization inference. Parser record iteration is not a full EVTX checksum validation.')
        return finish_import(case,folder,meta,records)
    except BaseException:
        shutil.rmtree(folder,ignore_errors=True);raise


def event_timeline(case):
    rows,manifests,issues=load_supplements(case,'events')
    # Same supplied log imported twice must not double-count its records. Preserve import provenance.
    unique={}
    for row in rows:
        ref=row['reference'];key=(ref['source_sha256'],ref['source_record'])
        if key not in unique:unique[key]={**row,'import_references':[ref]}
        else:unique[key]['import_references'].append(ref)
    return sorted(unique.values(),key=lambda x:(x.get('time_utc') or '9999',x.get('host',''),str(x.get('record_id','')))),manifests,issues
