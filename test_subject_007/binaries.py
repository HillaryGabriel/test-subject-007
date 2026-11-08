"""Computed SHA-256 evidence, not hash-shaped strings and not hashes of PIDs.

Memory reconstructed PE hashes are explicitly different representations from
acquired on-disk files. No automatic upload, reputation query or execution.
"""
from __future__ import annotations
import csv
import json
from pathlib import Path
import re
import shutil
import struct
from .supplemental import copy_source,finish_import,load_supplements
from .util import hash_file,fingerprint,Cancelled


def describe_binary(path):
    size=path.stat().st_size
    with path.open('rb') as f:
        head=f.read(64)
        if head.startswith(b'\x7fELF'):
            return {'format':'ELF','structure':'Header recognized; completeness not established'}
        if not head.startswith(b'MZ') or len(head)<64:
            return {'format':'Other','structure':'No PE/ELF header recognized; original bytes retained'}
        offset=struct.unpack_from('<I',head,0x3c)[0]
        if offset>1024*1024 or offset+24>size:return {'format':'PE candidate','structure':'Truncated/invalid PE header'}
        f.seek(offset);header=f.read(24)
        if not header.startswith(b'PE\x00\x00'):return {'format':'PE candidate','structure':'Invalid PE signature'}
        sections=struct.unpack_from('<H',header,6)[0];optional=struct.unpack_from('<H',header,20)[0]
        if sections<1 or sections>96 or offset+24+optional+sections*40>size:
            return {'format':'PE candidate','structure':'Truncated/invalid section table'}
        f.seek(offset+24+optional);table=f.read(sections*40)
        for i in range(sections):
            raw_size,raw_ptr=struct.unpack_from('<II',table,i*40+16)
            if raw_size and raw_ptr+raw_size>size:
                return {'format':'PE','structure':'Truncated raw-section content; partial artifact'}
    return {'format':'PE','structure':'Basic structure readable; complete/original bytes not established'}


def import_binary(case,source,pid=None,captured_path='',cancel=None):
    if pid is not None and (not isinstance(pid,int) or not 0<pid<=0xffffffff):
        raise ValueError('Enter a valid positive PID, or leave the association blank.')
    folder,meta=copy_source(case,source,'binary',cancel,max_size=2*1024**3)
    try:
        desc=describe_binary(case.root/meta['case_path'])
        entry={**meta,**desc,'pid':pid,'captured_path':str(captured_path),
               'representation':'acquired_file','hash_scope':'SHA-256 of analyst-supplied file bytes',
               'association':'Analyst-supplied PID/path link; equivalence to captured process image is not verified',
               'signature_status':'Not verified','integrity':'Computed during import','run_id':'','plugin':'',
               'reference':{'plugin':'supplement.binary','run_id':meta['id'],'row_id':1}}
        finish_import(case,folder,meta,[entry]);return entry
    except BaseException:
        shutil.rmtree(folder,ignore_errors=True);raise


def import_hash_intelligence(case,source,cancel=None):
    folder,meta=copy_source(case,source,'hash_intelligence',cancel,max_size=16*1024**2)
    try:
        with (case.root/meta['case_path']).open(encoding='utf-8-sig',newline='') as stream:
            reader=csv.DictReader(stream)
            required={'sha256','label','source','reference','representation'}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError('CSV must contain sha256,label,source,reference,representation columns.')
            records=[]
            for i,row in enumerate(reader,1):
                if cancel and cancel.is_set():raise Cancelled('Hash intelligence import cancelled.')
                if i>100000:raise ValueError('Limit is 100,000 supplied hash records.')
                digest=(row.get('sha256') or '').strip().casefold()
                if not re.fullmatch(r'[0-9a-f]{64}',digest):raise ValueError(f'Invalid SHA-256 at record {i}.')
                representation=row['representation'].strip()
                if representation not in ('acquired_file','memory_reconstructed_pe','memory_artifact'):
                    raise ValueError(f'Invalid representation at record {i}.')
                if not row['source'].strip() or not row['reference'].strip():raise ValueError(f'Source and reference required at record {i}.')
                label=row['label'].strip().casefold()
                if label not in ('malicious','suspicious','known_good'):raise ValueError(f'Invalid label at record {i}.')
                records.append({'sha256':digest,'label':label,'source':row['source'].strip(),
                    'reference_text':row['reference'].strip(),'representation':representation,
                    'intel_file_sha256':meta['sha256'],'source_record':i,'import_id':meta['id']})
        return finish_import(case,folder,meta,records)
    except BaseException:
        shutil.rmtree(folder,ignore_errors=True);raise


def artifact_inventory(case,runs,cancel=None):
    entries,manifests,issues=load_supplements(case,'binary')
    # Original supplied files are case-owned copies; verify actual bytes for each report.
    for item in entries:
        path=(case.root/item['case_path']).resolve()
        if not path.is_relative_to(case.root/'supplements'):
            item['integrity']='Invalid path';item['sha256']='';continue
        try:
            before=fingerprint(path);digest=hash_file(path,cancel)
            if fingerprint(path)!=before or digest!=item['sha256']:
                item['integrity']='Hash mismatch';item['sha256']='';issues.append('Imported binary failed verification: '+item['id'])
            else:item['integrity']='Verified copied bytes'
        except OSError:
            item['integrity']='Unavailable';item['sha256']=''
    for run in runs:
        if run.get('status') not in ('completed','completed_with_warnings'):continue
        plugin=run['plugin'];args=run.get('arguments',[])
        if '--dump' not in args and '.dumpfiles.' not in plugin and '.pedump.' not in plugin:continue
        root=case.root/'runs'/run['id']
        for output in run.get('output_files',[]):
            relative=Path(output.get('path',''))
            if not relative.parts or relative.parts[0]!='artifacts' or relative.is_absolute() or '..' in relative.parts:continue
            path=root/relative
            if path.is_symlink() or any(p.is_symlink() for p in path.parents if p!=case.root):continue
            try:
                if not path.resolve().is_relative_to((root/'artifacts').resolve()) or path.stat().st_size==0:continue
                if path.samefile(case.image):continue
                before=fingerprint(path);actual=hash_file(path,cancel)
                verified=actual==output.get('sha256') and fingerprint(path)==before
                name=path.name
                match=re.match(r'^(\d+)\.(.*?)\.0x[0-9a-f]+\.dmp$',name,re.I)
                pe=('.pslist.' in plugin or '.psscan.' in plugin) and bool(match)
                pid=int(match[1]) if pe else None
                entry={'id':run['id']+'/'+name,'case_path':str(path.relative_to(case.root)),
                       'original_path':'','size':before['size'],'sha256':actual if verified else '',
                       'pid':pid,'captured_path':'','process':match[2] if pe else '',
                       'representation':'memory_reconstructed_pe' if pe else 'memory_artifact',
                       'hash_scope':'SHA-256 of reconstructed PE bytes; not the original disk-file hash' if pe else 'SHA-256 of extracted memory/cache bytes; original-file equivalence unverified',
                       'association':'PID recovered from plugin output filename; correlate with run and process object',
                       'signature_status':'Not verified','integrity':'Verified extracted bytes' if verified else 'Output hash missing/mismatch',
                       'run_id':run['id'],'plugin':plugin,'reference':{'plugin':plugin,'run_id':run['id'],'row_id':0},
                       **describe_binary(path)}
                entries.append(entry)
                if not verified:issues.append('Extracted artifact hash mismatch/missing: '+name)
            except (OSError,ValueError) as exc:issues.append(str(path.name)+': '+str(exc))
    intelligence,im,ii=load_supplements(case,'hash_intelligence');issues+=ii
    hits=[]
    for item in entries:
        matching=[r for r in intelligence if item.get('sha256') and r['sha256']==item['sha256'] and r['representation']==item['representation']]
        labels={r['label'] for r in matching}
        if len(labels)>1:item['reputation']='Conflicting supplied intelligence';hits.append((item,matching))
        elif 'malicious' in labels:item['reputation']='Known-bad hash match (supplied intelligence)';hits.append((item,matching))
        elif 'suspicious' in labels:item['reputation']='Suspicious hash match (supplied intelligence)';hits.append((item,matching))
        elif 'known_good' in labels:item['reputation']='Known-good list match; not a runtime verdict'
        else:item['reputation']='Not assessed / no matching supplied intelligence'
        item['intelligence_matches']=matching
    findings=[]
    for item,matches in hits:
        findings.append({'priority':'High' if 'Known-bad' in item['reputation'] else 'Medium',
            'category':'Hash intelligence','title':item['reputation']+': '+Path(item['case_path']).name,
            'pid':item.get('pid'),'process':item.get('process',''),'status':'Intelligence match; validate source',
            'confidence':'Exact computed SHA-256 and representation match; intelligence is analyst supplied',
            'observation':item['sha256']+'\n'+item['hash_scope'],
            'context':'\n'.join(r['source']+' / '+r['reference_text']+' / '+r['label'] for r in matches),
            'interpretation':'A supplied list labels these bytes. This is not independent malware analysis, an active-infection verdict, or proof that a memory reconstruction equals its original file.',
            'action':'Validate intelligence provenance and applicability; preserve the original acquired binary and corroborate behavior.',
            'references':[item['reference']]})
    return entries,findings,issues
