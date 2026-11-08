"""Case-owned copies of analyst supplied evidence; never execute imported files."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid
from .util import atomic_json, fingerprint, hash_file, utc_now, Cancelled


def copy_source(case, source, kind, cancel=None, max_size=512*1024*1024):
    source=Path(source).expanduser().resolve(strict=True)
    before=fingerprint(source)
    if before['size']>max_size:
        raise ValueError(f'This import is limited to {max_size//(1024*1024)} MiB. Split the export or use a dedicated parser.')
    if source.samefile(case.image):
        raise ValueError('The complete memory image is not an executable or supplemental log. Use memory analysis instead.')
    folder=case.root/'supplements'/uuid.uuid4().hex
    folder.mkdir(parents=True,mode=0o700)
    suffix=source.suffix[:15] if source.suffix else '.bin'
    target=folder/('source'+suffix)
    digest=hashlib.sha256()
    try:
        with source.open('rb') as src,target.open('xb') as dst:
            while chunk:=src.read(1024*1024):
                if cancel and cancel.is_set():raise Cancelled('Import cancelled; no successful import recorded.')
                dst.write(chunk);digest.update(chunk)
            dst.flush();os.fsync(dst.fileno())
        if fingerprint(source)!=before:
            raise ValueError('Source changed during import. Preserve a stable working copy and retry.')
        try:target.chmod(0o600)
        except OSError:pass
        return folder,{'id':folder.name,'kind':kind,'imported_utc':utc_now(),'original_path':str(source),
                      'case_path':str(target.relative_to(case.root)),'size':before['size'],'sha256':digest.hexdigest()}
    except BaseException:
        shutil.rmtree(folder,ignore_errors=True)
        raise


def finish_import(case,folder,meta,records):
    path=folder/'records.json'
    atomic_json(path,records)
    meta['records_sha256']=hash_file(path)
    atomic_json(folder/'manifest.json',meta)
    case.audit('supplement_imported',{'id':meta['id'],'kind':meta['kind'],'source_sha256':meta['sha256'],
                                    'manifest_sha256':hash_file(folder/'manifest.json'),'records':len(records)})
    return meta


def load_supplements(case,kind):
    records,manifests,issues=[],[],[]
    # The case remains local and mutable; match the manifest to its audit entry.
    approved={}
    audit=case.root/'audit.jsonl'
    if audit.exists():
        for line in audit.read_text(encoding='utf-8').splitlines():
            item=json.loads(line)
            if item.get('action')=='supplement_imported':approved[item['detail']['id']]=item['detail']
    for path in sorted((case.root/'supplements').glob('*/manifest.json')):
        if path.is_symlink() or path.parent.is_symlink():
            issues.append('Supplement symlink refused: '+path.parent.name);continue
        try:
            meta=json.loads(path.read_text(encoding='utf-8'))
            if meta.get('kind')!=kind:continue
            entry=approved.get(path.parent.name,{})
            if hash_file(path)!=entry.get('manifest_sha256'):
                raise ValueError('Manifest does not match the recorded audit digest')
            data=path.parent/'records.json'
            if data.is_symlink() or hash_file(data)!=meta['records_sha256']:
                raise ValueError('Supplement records failed integrity verification')
            source=(case.root/meta['case_path']).resolve(strict=True)
            if (case.root/meta['case_path']).is_symlink() or not source.is_relative_to(path.parent.resolve()) or source.stat().st_size!=meta['size']:
                raise ValueError('Supplement source is missing, moved or has changed size')
            if hash_file(source)!=meta['sha256']:
                raise ValueError('Supplement source bytes failed SHA-256 verification')
            manifests.append(meta)
            records.extend(json.loads(data.read_text(encoding='utf-8')))
        except (OSError,ValueError,KeyError,TypeError) as exc:
            issues.append(path.parent.name+': '+str(exc))
    return records,manifests,issues
