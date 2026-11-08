"""Explicit analyst disposition, scoped to the evidence state at recording."""
import hashlib
import json
from .util import utc_now

DISPOSITIONS=('Unresolved','Suspicious activity - validation pending','Authorized activity supported','Confirmed malicious activity - analyst assessment','No evidence found within reviewed scope')


def evidence_state(case):
    runs=[(r['id'],r['status'],r.get('output_files',[])) for r in case.runs()]
    supplements=[(p.parent.name,hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted((case.root/'supplements').glob('*/manifest.json')) if not p.is_symlink()]
    return hashlib.sha256(json.dumps([case.metadata['sha256'],runs,supplements],sort_keys=True).encode()).hexdigest()


def save_assessment(case,disposition,reason,references):
    if disposition not in DISPOSITIONS:raise ValueError('Choose a supported disposition.')
    if not reason.strip() or not references.strip():raise ValueError('A reason and supporting evidence references are required. Do not use the automated findings count as evidence of innocence or guilt.')
    value={'disposition':disposition,'reason':reason.strip(),'references':references.strip(),
           'analyst':case.metadata.get('analyst',''),'utc':utc_now(),'evidence_state':evidence_state(case)}
    case.audit('analyst_assessment_recorded',value);case.metadata['analyst_assessment']=value;case.save()
    return value
