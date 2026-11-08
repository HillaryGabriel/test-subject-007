"""Explainable executable-location and parent-context checks, not name-only AV."""
from __future__ import annotations
from collections import defaultdict
from .triage_rules import primary_path,windows_path_assessment,basename,command_text,first_token,INTERPRETERS,MIMICS
from .chronology import as_datetime,timestamp


def int_value(v):
    try:return int(str(v),16 if str(v).lower().startswith('0x') else 10)
    except (ValueError,TypeError):return None


def review_processes(processes,execution,system_root,system):
    paths=defaultdict(list)
    for ref,row in execution:
        pid=int_value(row.get('PID'));path=primary_path(row)
        if path and pid is not None:paths[pid].append((ref,row,path))
    inventory=[];findings=[]
    for pid in sorted(set(processes)|set(paths)):
        related=processes.get(pid,[])
        identities={(r.get('Offset(V)',r.get('Offset','')),r.get('CreateTime','')) for _,r in related}
        ambiguous=len({v[0] for v in identities if v[0]})>1
        row=related[0][1] if related else (paths[pid][0][1] if paths[pid] else {})
        parent=int_value(row.get('PPID'))
        name=str(row.get('ImageFileName',row.get('Process',row.get('COMM',''))))
        actual_paths=list(dict.fromkeys(x[2] for x in paths.get(pid,[]) if ('\\' in x[2] or '/' in x[2])))
        refs=[r for r,_ in related]+[r for r,_,_ in paths.get(pid,[])]
        created=as_datetime(row.get('CreateTime'))
        parents=[]
        for pref,prow in processes.get(parent,[]):
            start=as_datetime(prow.get('CreateTime'));end=as_datetime(prow.get('ExitTime'))
            if created and start and start<=created and (not end or end>=created):
                parents.append((pref,prow))
        parent_names=list(dict.fromkeys(str(p.get('ImageFileName',p.get('Process',''))) for _,p in parents))
        command=next((command_text(r) for _,r,_ in paths.get(pid,[]) if command_text(r)), '')
        inventory.append({'pid':pid,'process':name,'ppid':parent,'paths':actual_paths,'command':command,
            'created':row.get('CreateTime',''),'exited':row.get('ExitTime',''),'object_identities':list(identities),
            'identity_status':'Ambiguous/reused PID; do not join by PID alone' if ambiguous else 'Single observed identity; not authenticated',
            'parent_context':parent_names,'location_baseline':('Captured NtSystemRoot: '+system_root) if system_root else 'OS root unavailable; system-directory checks withheld','hash_status':'No binary bytes collected','sha256':'','references':refs})
        # Contradictory PIDs remain in the inventory, but cannot support a confident path attribution.
        if system=='Windows' and not ambiguous:
            for path in actual_paths:
                reason=windows_path_assessment(path,system_root) if (system_root or basename(path) in MIMICS) else ''
                if not reason:continue
                findings.append({'priority':'High','category':'Process integrity','title':'Executable identity/location anomaly: '+(name or basename(path)),
                    'pid':pid,'process':name,'status':'Suspicious location/name; not confirmed malicious',
                    'confidence':'Captured path compared against a small explicit Windows baseline',
                    'observation':path,'context':reason+'\nCaptured OS root: '+system_root,
                    'interpretation':'An unexpected path or look-alike name is an investigation lead. Verify the actual executable, architecture, OS layout, signature and approved installation.',
                    'action':'Collect the executable, compute SHA-256 and validate provenance. Compare the full process identity and endpoint telemetry before remediation.',
                    'references':[ref for ref,_,p in paths[pid] if p==path]+[ref for ref,_ in related]})
        # A parent named Office alone is insufficient: require a valid child time,
        # one parent identity valid at that time and an actual interpreter token.
        parent_ids={p.get('Offset(V)',p.get('Offset','')) for _,p in parents}
        child=basename(first_token(command)).removesuffix('.exe')
        if not ambiguous and created and len(parent_ids)==1 and parent_names and child in INTERPRETERS:
            if any(p.casefold() in ('winword.exe','excel.exe','powerpnt.exe','outlook.exe') for p in parent_names):
                findings.append({'priority':'Medium','category':'Command execution','title':'Office-parent interpreter execution: '+(name or child),
                    'pid':pid,'process':name,'status':'Execution-chain lead','confidence':'Parent PID with compatible process lifetime; causal relationship still requires validation',
                    'observation':command,'context':'Parent PID '+str(parent)+' / '+', '.join(parent_names)+'; child created '+str(row.get('CreateTime')),
                    'interpretation':'Office automation can be approved. This relationship warrants script/macro and user-action review, not automatic malware classification.',
                    'action':'Review document provenance, macro/script content and EDR process-creation events.',
                    'references':refs+[ref for ref,_ in parents]})
    return inventory,findings
