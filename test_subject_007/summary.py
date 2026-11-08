"""Evidence-based report model and local observable extraction.

Only latest attempts per plugin feed aggregates. Full CSV exports retain every
attempt. Observables are unvalidated strings, never automatically labelled malware.
"""
from __future__ import annotations
from collections import Counter
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from urllib.parse import urlsplit
from .case import verify_audit
from .diagnostics import diagnose
from .results import iter_rows, query_rows
from .util import Cancelled, utc_now
from .profiles import signature
from .contextual import contextual_matches
from .findings import inspect_case

SUCCESS = {'completed', 'completed_with_warnings'}
URL = re.compile(r'\bhttps?://[^\s<>"\x00-\x20]+', re.I)
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]{0,45}(?![\w:])')
DOMAIN = re.compile(r'(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|ph|uk|de|ru|cn|info|biz|xyz|top|online|site|local|au|ca|jp|co|us|dev|app)(?![\w.-])', re.I)
HASH = re.compile(r'(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-zA-Z])')


def observables(text: str):
    """Literal pattern extraction; no lookups, requests, or execution."""
    seen = set()
    for pattern, kind in ((URL, 'URL'), (IPV4, 'IP address'), (IPV6, 'IP address'),
                          (DOMAIN, 'Domain candidate'), (HASH, 'Hash candidate')):
        for match in pattern.finditer(text):
            value = match.group(0).rstrip('.,;)]}')
            note = 'Unvalidated; pattern match only'
            if kind == 'IP address':
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                value = str(address)
                note = 'Globally routable address' if address.is_global else 'Non-global address (private, reserved, loopback or local)'
            elif kind == 'URL':
                try:
                    if not urlsplit(value).hostname:
                        continue
                except ValueError:
                    continue
            elif kind == 'Hash candidate':
                value = value.lower()
                note = {32: 'MD5-length', 40: 'SHA-1-length', 64: 'SHA-256-length'}[len(value)] + '; provenance not established'
            else:
                value = value.lower()
            if (kind, value) not in seen:
                seen.add((kind, value))
                yield kind, value, note


def get_observables(case, query='', limit=250, offset=0):
    database = case.root / 'observables.sqlite'
    if not database.exists():
        return [], 0
    condition = "WHERE instr(lower(value), ?) > 0 OR instr(lower(kind), ?) > 0" if query else ''
    args = [query.casefold(), query.casefold()] if query else []
    with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        total = db.execute(f'SELECT count(*) FROM observables {condition}', args).fetchone()[0]
        records = db.execute(f'SELECT kind,value,occurrences,note,plugin,run_id,row_id FROM observables {condition} '
                             'ORDER BY occurrences DESC, kind, value LIMIT ? OFFSET ?', [*args, limit, offset])
        return [dict(zip(('kind','value','occurrences','note','plugin','run_id','row_id'), r)) for r in records], total


def build_summary(case, cancel=None, emit=lambda *_: None):
    runs = sorted(case.runs(), key=lambda r: (r.get('started_utc', ''), r['id']), reverse=True)
    latest = {}
    for run in runs:
        latest.setdefault(signature(run), run)
    current = list(latest.values())
    fd, tmp = tempfile.mkstemp(prefix='.observables-', suffix='.sqlite', dir=case.root)
    os.close(fd)
    count = 0
    categories = Counter()
    process_ids = set()
    coverage, failures = [], []
    excluded_observables = []
    try:
        with closing(sqlite3.connect(tmp)) as db, db:
            db.execute('CREATE TABLE observables(kind TEXT,value TEXT,occurrences INTEGER,note TEXT,plugin TEXT,run_id TEXT,row_id INTEGER, PRIMARY KEY(kind,value))')
            for run in current:
                if cancel and cancel.is_set():
                    raise Cancelled('Report analysis cancelled. Prior reports remain unchanged.')
                folder = case.root / 'runs' / run['id']
                columns, _, actual = query_rows(folder / 'results.sqlite', limit=1)
                coverage.append({'plugin': run['plugin'], 'status': run['status'], 'rows': actual, 'run_id': run['id'], 'arguments':run.get('arguments',[])})
                if run['status'] not in SUCCESS:
                    failures.append({'plugin': run['plugin'], 'run_id': run['id'],
                                     **diagnose(run, folder)})
                # Integrity warnings/running output must never enter artifact aggregates.
                if run['status'] in ('integrity_warning', 'running') or not columns or columns[0] != 'TreeDepth':
                    continue
                emit('status', 'Summarizing ' + run['plugin'] + ' and extracting unvalidated observables...')
                for row_id, row in iter_rows(folder / 'results.sqlite'):
                    count += 1
                    if count % 250 == 0:
                        if cancel and cancel.is_set():
                            raise Cancelled('Report analysis cancelled.')
                        emit('status', f'Summarized {count:,} records; observables are local pattern matches only.')
                    if '.pslist.' in run['plugin'] and run['status'] in SUCCESS and row.get('PID'):
                        process_ids.add(row['PID'])
                    # Match fields in context; retain exclusions for audit instead of silently discarding them.
                    matches, exclusions = contextual_matches(row, run['plugin'], observables)
                    excluded_observables.extend({**item,'plugin':run['plugin'],'run_id':run['id'],'row_id':row_id} for item in exclusions)
                    for kind, value, note in matches:
                        db.execute('INSERT INTO observables VALUES (?,?,?,?,?,?,?) '
                                   'ON CONFLICT(kind,value) DO UPDATE SET occurrences=occurrences+1',
                                   (kind,value,1,note,run['plugin'],run['id'],row_id))
                    if count % 5000 == 0:
                        db.commit()
            for kind, number in db.execute('SELECT kind,count(*) FROM observables GROUP BY kind'):
                categories[kind] = number
            db.commit()
        os.replace(tmp, case.root / 'observables.sqlite')
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    complete = sum(r['status'] in SUCCESS for r in current)
    observable_rows, total = get_observables(case)
    if not current:
        assessment = 'NOT ANALYZED'
        summary = 'No plugin runs are recorded. This report documents the imported image only; no security conclusion is supported.'
    elif not complete:
        assessment = 'ANALYSIS INCOMPLETE'
        summary = 'None of the latest plugin attempts completed successfully. Resolve the diagnostics before assessing the captured system. Zero recovered rows do not mean zero threats.'
    elif complete < len(current):
        assessment = 'PARTIAL COVERAGE'
        summary = f'{complete} of {len(current)} latest plugin attempts completed. Failed or partial attempts limit coverage; review their diagnostics and rerun as needed.'
    else:
        assessment = 'READY FOR ANALYST REVIEW'
        summary = f'All {complete} latest plugin attempts completed, possibly with logged warnings. This is execution coverage, not a clean-system or malware verdict.'
    if case.metadata.get('verification') == 'mismatch' or any(r['status']=='integrity_warning' for r in current):
        assessment = 'INTEGRITY WARNING'
        summary = 'Evidence verification failed or source metadata changed. Do not rely on this analysis until evidence integrity is resolved.'
    observations = []
    not_run = case.metadata.get('last_batch', {}).get('not_run', [])
    if not_run:
        observations.append(f'{len(not_run)} requested plugins did not run in the most recent batch. This limits coverage even when earlier runs exist.')
    reviewed = inspect_case(case, current, cancel, emit)
    if process_ids:
        observations.append(f'{reviewed["plausible_process_objects"]:,} process objects passed basic plausibility checks; {reviewed["excluded_pslist_rows"]:,} pslist rows failed those checks. Passing is not proof of validity or legitimacy.')
    observations.append(f'{reviewed["actionable_count"]} actionable review items; {reviewed["context_count"]} context groups. No automatic infection verdict is made.')
    observations.append(f'{len(reviewed["suppressed_records"])} background/configuration matches kept outside actionable findings; originals and suppression reasons are preserved.')
    observations.append(f'{len(reviewed["binary_evidence"])} binary artifacts recorded. Hashes identify supplied/recovered bytes, not PIDs or necessarily the original on-disk executable.')
    if reviewed['event_timeline']:
        observations.append(f'{len(reviewed["event_timeline"])} imported authentication/session events. Event times, memory-object times and capture time remain distinct.')
    elif case.metadata.get('investigation_profile') == 'Remote access investigation':
        observations.append('No supplemental authentication logs imported. Memory/network timestamps alone do not establish RDP authentication, duration or authorization.')
    network = [r for r in coverage if any(key in r['plugin'] for key in ('.netscan.', '.netstat.', '.sockstat.'))]
    if network:
        observations.append(f'{sum(r["rows"] for r in network):,} network artifact records are indexed in the latest network-plugin attempts. Records may overlap and are not all established connections.')
    suspicious = [r for r in coverage if '.malfind.' in r['plugin']]
    if suspicious:
        observations.append(f'{sum(r["rows"] for r in suspicious):,} malfind records require context-specific review. A match alone is not proof of injected malware.')
    observations.append(f'{total:,} distinct observable strings were automatically extracted from latest-attempt indexed records. No external reputation lookup or automatic malicious classification was performed.')
    recommendations = []
    for failure in failures:
        for item in failure['actions']:
            if item not in recommendations:
                recommendations.append(item)
    recommendations += ['Validate candidate indicators and suspicious artifacts against endpoint, authentication, application and network logs.',
                        'Review case notes and run logs before making attribution, blocking or containment decisions.']
    recommendations = list(dict.fromkeys([f['action'] for f in reviewed['findings'] if f.get('layer')=='Finding'] + recommendations))
    if reviewed['event_issues'] or reviewed['binary_issues']:
        observations.append('Supplemental evidence integrity/read warnings: ' + '; '.join(reviewed['event_issues']+reviewed['binary_issues']))
    audit_ok, audit_count, audit_head = verify_audit(case.root / 'audit.jsonl')
    if reviewed['quality_flags'] and assessment == 'READY FOR ANALYST REVIEW':
        assessment = 'REVIEW REQUIRED / DATA QUALITY WARNINGS'
    missing = case.metadata.get('profile_missing', [])
    if missing:
        observations.insert(0, f'{len(missing)} requested profile plugins were unavailable: ' + ', '.join(missing))
        if assessment == 'READY FOR ANALYST REVIEW':
            assessment = 'PARTIAL PROFILE COVERAGE'
    preflight = case.metadata.get('last_batch', {}).get('preflight', {})
    planning_gaps = list(preflight.get('deferred', []))
    planning_gaps += [{'plugin': name, 'status': 'Unavailable', 'reason': 'Not available in the installed catalog.', 'job': 0}
                      for name in preflight.get('unavailable', [])]
    if planning_gaps:
        observations.insert(0, f'{len(planning_gaps)} requested tasks were not queued at preflight. Reasons are listed under Investigation scope and planning-not-run.csv.')
        if assessment not in ('INTEGRITY WARNING', 'NOT ANALYZED', 'ANALYSIS INCOMPLETE'):
            assessment = 'PARTIAL INVESTIGATION COVERAGE'
        summary += f' {len(planning_gaps)} requested tasks were not run because inputs or plugins were unavailable; completion applies only to queued tasks.'
        recommendations.insert(0, 'Configure deferred plugin inputs or install missing plugins, then rerun the required tasks. No findings from an unexecuted task can be inferred.')
    if not_run and assessment not in ('INTEGRITY WARNING', 'NOT ANALYZED', 'ANALYSIS INCOMPLETE'):
        assessment = 'PARTIAL INVESTIGATION COVERAGE'
    assessment_value=case.metadata.get('analyst_assessment')
    if assessment_value:
        from .assessment import evidence_state
        reviewed['analyst_assessment_stale']=bool(assessment_value.get('evidence_state')!=evidence_state(case) or reviewed['binary_issues'] or reviewed['event_issues'] or not audit_ok)
    if not audit_ok:
        assessment='INTEGRITY WARNING'
        summary='Case audit verification failed. Preserve this case and resolve integrity before relying on conclusions.'
    return {**reviewed, 'preflight':preflight, 'planning_gaps':planning_gaps, 'excluded_observables':excluded_observables,
            'investigation_goal':case.metadata.get('investigation_goal',{}),
            'investigation':case.metadata.get('investigation_profile','Custom / existing runs'),
            'generated_utc': utc_now(), 'case': dict(case.metadata), 'runs': runs, 'latest': coverage,
            'assessment': assessment, 'summary': summary, 'observations': observations,
            'recommendations': recommendations[:10], 'failures': failures,
            'complete_latest': complete, 'records_latest': sum(r['rows'] for r in coverage),
            'observable_total': total, 'observable_categories': dict(categories),
            'observable_preview': observable_rows, 'status_counts': dict(Counter(r['status'] for r in runs)),
            'notes': case.notes(), 'audit_ok': audit_ok, 'audit_count': audit_count, 'audit_head': audit_head,
            'limits': 'Charts aggregate the latest attempt per plugin and argument set, except the all-attempt execution chart. '
                      'A failed latest attempt is not replaced with an older success. Records can overlap across plugins. '
                      'Observable extraction searches indexed plugin text, not raw RAM; domain/hash matches are heuristic. '
                      'Partial records remain incomplete. Capture quality, matching symbols and plugin support constrain coverage. '
                      'A process or account artifact does not establish the identity of its operator.'}
