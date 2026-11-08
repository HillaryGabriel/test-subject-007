#!/usr/bin/env python3
"""Publish ONLY the reviewed source manifest using an already authenticated gh CLI.

New repositories are private. Existing repositories are updated on a new branch,
never by force-pushing or deleting the repository. No credentials are collected.
"""
from __future__ import annotations
import argparse
import datetime
import shutil
import re
import subprocess
import sys
from pathlib import Path
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(argv, cwd=ROOT, capture=True):
    proc=subprocess.run(argv,cwd=cwd,text=True,encoding='utf-8',errors='replace',capture_output=capture,shell=False)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout or 'Command failed').strip() if capture else 'Command failed; review output above.')
    return proc.stdout.strip() if capture else ''


def safe_path(root, name):
    root = root.resolve()
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid source path: ' + name)
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise ValueError('Source path escapes its root: ' + name)
    for item in [path, *path.parents]:
        if item == root:
            break
        if item.is_symlink():
            raise ValueError('Symlink paths are not published: ' + name)
    return path


def source_files(root=ROOT):
    paths=[]
    for line in (root/'PUBLIC-FILES.txt').read_text(encoding='utf-8').splitlines():
        name=line.strip()
        if not name or name.startswith('#'):continue
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Invalid manifest path: '+name)
        path=safe_path(root, name)
        if not path.is_file():
            raise ValueError('Missing or unsafe source file: '+name)
        if path.stat().st_size>10*1024*1024:
            raise ValueError('Unexpectedly large source file; inspect it before publishing: '+name)
        paths.append(name)
    if not paths:raise ValueError('The public source manifest is empty.')
    return paths


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',default='test-subject-007',help='New private repository name, or OWNER/NAME')
    parser.add_argument('--existing',help='Existing OWNER/NAME: clone and publish a new review branch')
    args=parser.parse_args()
    for command in ('git','gh'):
        if not shutil.which(command):raise RuntimeError(command+' is required for CLI publication. The browser upload guide does not require it.')
    run(['gh','auth','status'])
    files=source_files()
    owner=run(['gh','api','user','--jq','.login'])
    repo=args.existing or (args.name if '/' in args.name else owner+'/'+args.name)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Use a repository identifier in OWNER/NAME format.')
    print('Target:',repo)
    print('New review branch in existing repository.' if args.existing else 'New PRIVATE repository.')
    print('\nFiles to publish (evidence and case folders are NOT included):\n'+'\n'.join(files))
    if input('\nReview the list. Type PUBLISH to continue: ').strip()!='PUBLISH':
        print('Nothing published.');return
    # Git author identity is required, but never invented by this script.
    for field in ('user.name','user.email'):
        if not run(['git','config','--get',field]):raise RuntimeError('Set your correct Git '+field+' before publishing.')
    if args.existing:
        target=ROOT/'.publish-work'/uuid.uuid4().hex[:10];target.parent.mkdir(exist_ok=True)
        run(['gh','repo','clone',repo,str(target)])
        branch='workbench-refresh-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        run(['git','switch','-c',branch],target)
        for name in files:
            dest=safe_path(target, name)
            dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dest)
    else:
        target=ROOT
        if (ROOT/'.git').exists():
            if run(['git','remote']):raise RuntimeError('This folder already has a remote. Use --existing OWNER/NAME or the documented branch workflow.')
        else:run(['git','init','-b','main'])
    run(['git','add','--',*files],target)
    staged=run(['git','diff','--cached','--name-only'],target).splitlines()
    extra=set(staged)-set(files)
    if extra:raise RuntimeError('Unexpected staged files. Review and unstage them before publishing: '+', '.join(sorted(extra)))
    if not staged:
        print('No source changes to publish.');return
    print(run(['git','diff','--cached','--stat'],target))
    run(['git','commit','-m','Improve investigation workspace, live logs and evidence reporting'],target)
    if args.existing:
        run(['git','push','--set-upstream','origin',branch],target,capture=False)
        print('Pushed branch:',branch,'\nOpen a pull request and review the changes before merging.')
    else:
        run(['gh','repo','create',repo,'--private','--source',str(target),'--remote','origin','--push'],target,capture=False)
    print(run(['gh','repo','view',repo,'--json','url','--jq','.url'],target))

if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError,KeyboardInterrupt) as exc:
        print('Publication stopped:',exc,file=sys.stderr);raise SystemExit(1)
