"""Conservative, source-linked review rules. Never a standalone malware verdict.

Original rows are kept unchanged. Quality flags and generated findings are separate
products. All references identify the run and one-based indexed row.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import re
from .results import iter_rows
from .util import Cancelled
from .chronology import as_datetime, memory_timeline
from .triage_rules import script_evidence, execution_signals, primary_path, command_text
from .process_review import review_processes
from .binaries import artifact_inventory
from .eventlogs import event_timeline
from .targeted import (remote_matches, remote_findings, network_context, port_findings, token_match, SEARCH_PLUGINS)

SUCCESS = {'completed', 'completed_with_warnings'}
PRIORITY = {'High': 0, 'Medium': 1, 'Review': 2, 'Informational': 3}
EMPTY = {'', '-', "'-", 'N/A', 'None'}
SCRIPT = re.compile(r'\bjavaw?(?:\.exe)?\b|\.(?:jar|vbs|vbe|wsf|ps1|psm1|hta|js|jse|sh|py)\b|\b(?:wscript|cscript|powershell|pwsh|mshta|bash|python3?)(?:\.exe)?\b', re.I)
ENCODED = re.compile(r'\b(?:powershell|pwsh)(?:\.exe)?\b.*?\s-(?:enc|encodedcommand|e)\s+\S+', re.I)
STARTUP = re.compile(r'\\start menu\\programs\\startup\\[^\\\r\n]+\.(?:exe|com|scr|bat|cmd|vbs|js|ps1)$', re.I)
SHELL = re.compile(r'\b(?:powershell|pwsh|cmd|wscript|cscript|mshta)(?:\.exe)?\b', re.I)


def as_int(value):
    try:
        s = str(value).strip()
        return int(s, 16 if s.lower().startswith('0x') else 10)
    except (ValueError, TypeError):
        return None


def dt(value):
    return as_datetime(value)


def quality_reasons(row, capture=None):
    reasons = []
    pid, ppid = as_int(row.get('PID')), as_int(row.get('PPID'))
    if pid is None or pid < 0 or pid > 0xffffffff:
        reasons.append('Invalid or out-of-range PID')
    if 'PPID' in row and (ppid is None or ppid < 0 or ppid > 0xffffffff):
        reasons.append('Invalid or out-of-range parent PID')
    name = row.get('ImageFileName', row.get('Process', row.get('COMM', '')))
    if name in EMPTY or '\ufffd' in name or any(ord(c) < 32 for c in name):
        reasons.append('Missing or undecodable process name')
    threads = as_int(row.get('Threads'))
    if threads is not None and threads > 1000000:
        reasons.append('Implausible thread count')
    for field in ('CreateTime', 'ExitTime'):
        date = dt(row.get(field))
        if date and date.year < 2000:
            reasons.append(field + ' is implausibly old')
        if capture and date and date > capture + timedelta(minutes=1):
            reasons.append(field + ' is later than captured system time; verify acquisition timing')
    return reasons


def reference(run, number):
    return {'plugin': run['plugin'], 'run_id': run['id'], 'row_id': number}


def executable(row):
    for field in ('Path', 'Audit'):
        text = row.get(field, '').strip()
        if text not in EMPTY and re.search(r'\.(exe|com|scr)$', text, re.I):
            return text
    command = row.get('Args', row.get('Cmd', '')).strip()
    match = re.match(r'^"([^"]+)"|^([^\s]+)', command)
    return (match[1] or match[2]) if match else ''


def inspect_case(case, runs, cancel=None, emit=lambda *_: None):
    """Group related artifacts, retain every evidence reference and every quality flag."""
    valid_runs = [r for r in runs if r['status'] in SUCCESS]
    process_by_pid, modules = defaultdict(list), defaultdict(list)
    malformed, regions, findings, network = [], [], [], []
    script_matches, keyword_matches, remote_items = [], [], []
    suppressed, execution_rows = [], []
    system_root = ''
    process_seen, valid_pslist, invalid_pslist = set(), set(), 0
    capture = None
    keywords = [str(x).casefold() for x in case.metadata.get('investigation_terms', []) if str(x).strip()]
    # The snapshot time is needed before validating process dates.
    for run in valid_runs:
        if '.info.' in run['plugin']:
            for number, row in iter_rows(case.root / 'runs' / run['id'] / 'results.sqlite'):
                if row.get('Variable') == 'SystemTime':
                    capture = dt(row.get('Value'))
                if row.get('Variable') == 'NtSystemRoot':
                    system_root = row.get('Value') or system_root
    gathered = defaultdict(list)
    total = 0
    for run in valid_runs:
        for number, row in iter_rows(case.root / 'runs' / run['id'] / 'results.sqlite'):
            total += 1
            if total % 1000 == 0:
                if cancel and cancel.is_set():
                    raise Cancelled('Finding review cancelled; original rows are preserved.')
                emit('status', f'Correlating evidence and checking quality: {total:,} records reviewed')
            plugin, ref = run['plugin'], reference(run, number)
            pid = as_int(row.get('PID'))
            is_proc = any(k in plugin for k in ('.pslist.', '.psscan.', '.pstree.'))
            issues = quality_reasons(row, capture) if is_proc and 'PID' in row else []
            if issues:
                malformed.append({**ref, 'pid': row.get('PID',''), 'process': row.get('ImageFileName', ''),
                                  'reasons': '; '.join(issues), 'record': row})
                if '.pslist.' in plugin:
                    invalid_pslist += 1
            elif is_proc:
                process_by_pid[pid].append((ref, row))
                if '.pslist.' in plugin:
                    valid_pslist.add((row.get('Offset(V)', row.get('Offset', '')), pid, row.get('CreateTime', '')))
                    process_seen.add(pid)
            if '.dlllist.' in plugin:
                base, size = as_int(row.get('Base')), as_int(row.get('Size'))
                if base is not None and size is not None and size > 0:
                    modules[pid].append((base, base + size, row, ref))
            if '.malfind.' in plugin:
                regions.append({**ref, 'pid': pid, 'process': row.get('Process',''),
                                'start': row.get('Start VPN',''), 'end': row.get('End VPN',''),
                                'protection': row.get('Protection',''), 'record': row})
            if not issues:
                for tool in remote_matches(plugin,row):
                    remote_items.append({'tool':tool,'pid':pid,'record':row,'reference':ref})
            if any(k in plugin for k in SEARCH_PLUGINS):
                text = '\n'.join(str(v) for v in row.values())
                context, exclusion = script_evidence(plugin, row)
                if context:
                    script_matches.append({**ref, 'pid': pid, 'record': row, **context})
                if exclusion:
                    suppressed.append({**ref, 'pid': pid, 'reason': exclusion, 'record': row})
                if not issues:
                    for kind, priority, rationale in execution_signals(plugin, row):
                        gathered[(kind, pid, command_text(row))].append((ref, row, command_text(row)))
                    if any(k in plugin for k in ('.cmdline.', '.pstree.', '.psaux.')):
                        execution_rows.append((ref, row))
                if not issues:
                    if any(k in plugin for k in ('.cmdline.', '.pstree.')):
                        path = primary_path(row)
                        if STARTUP.search(path):
                            gathered[('Startup executable', pid, path.casefold())].append((ref, row, path))
                    if '.printkey.' in plugin and context and context['kind'] == 'Configured autostart command':
                        gathered[('Script interpreter in Run key', pid, text)].append((ref, row, text))
                    if '.svcscan.' in plugin:
                        command = command_text(row)
                        if re.search(r'\\(?:temp|users\\public)\\', primary_path(row), re.I):
                            gathered[('Service in writable directory', pid, command)].append((ref, row, command))
            if not '.info.' in plugin:
                for term in keywords:
                    if token_match(term,row):
                        keyword_matches.append({**ref, 'term': term, 'pid': pid, 'record': row})
            if any(k in plugin for k in ('.netscan.', '.netstat.', '.sockstat.')):
                network.append({**ref, 'record': row})
    for (kind, pid, _), entries in gathered.items():
        refs = [e[0] for e in entries]
        related = process_by_pid.get(pid, [])
        proc = related[0][1] if related else entries[0][1]
        # Do not associate a PID-only finding with contradictory reused process identities.
        offsets = {r.get('Offset(V)', r.get('Offset','')) for _,r in related if r.get('Offset(V)',r.get('Offset',''))}
        ambiguous = len(offsets) > 1
        name = proc.get('ImageFileName', proc.get('Process',''))
        parent = as_int(proc.get('PPID'))
        created = dt(proc.get('CreateTime'))
        parent_names = []
        for _, prow in process_by_pid.get(parent, []):
            when = dt(prow.get('CreateTime'))
            if not created or not when or when <= created:
                n = prow.get('ImageFileName', '')
                if n and n not in parent_names:
                    parent_names.append(n)
        finding = {
            'priority': 'High' if kind in ('Startup executable','Download-and-execute command pattern','MSHTA remote or inline content','Download piped to shell') else 'Medium',
            'category': 'Persistence' if 'Startup' in kind or 'Run key' in kind or 'Service' in kind else 'Command execution',
            'title': f'{kind}: {name or "artifact"}' + (f' (PID {pid})' if pid is not None else ''),
            'pid': pid, 'process': name, 'status': 'Needs analyst validation',
            'observation': entries[0][2], 'confidence': 'Artifact observed; maliciousness unconfirmed',
            'context': ('Parent PID ' + str(parent) + ' / ' + ', '.join(parent_names) + '; creation time ' + str(proc.get('CreateTime', 'not available'))) if related else 'No corroborating process inventory available.',
            'interpretation': 'This is an investigation lead, not a malware verdict. Validate authorization, provenance and timeline before containment.',
            'action': 'Preserve the original file and metadata, compute SHA-256 on the preserved file, verify its signature and correlate creation/execution telemetry. Do not execute recovered files.',
            'references': refs + [r for r, _ in related],
        }
        if ambiguous:
            finding['context'] += ' Multiple process objects share this PID; identity correlation is ambiguous.'
        findings.append(finding)
    # Ordinary interpreter/file references stay in the context CSV; only concrete
    # execution or persistence signals above become actionable review items.
    for term in keywords:
        group = [g for g in keyword_matches if g['term'] == term]
        if group:
            findings.append({'priority':'Review','category':'Analyst search','title':f'Analyst term matched: {term}',
                'pid':None,'process':'','status':'Unvalidated match','confidence':'Boundary-aware indicator or literal text match',
                'observation':f'{len(group)} indexed records match the supplied term. First source record:\n' + '\n'.join(f'{k}: {v}' for k,v in group[0]['record'].items() if v and k != 'TreeDepth'),
                'context':'Search covers selected successful plugin outputs, not every byte of raw RAM.',
                'interpretation':'An analyst-selected term is not automatically a malicious indicator.',
                'action':'Review the source records and establish their meaning.',
                'references':[{k:g[k] for k in ('plugin','run_id','row_id')} for g in group]})
    # Candidate executable regions are grouped, not counted as infections.
    groups = defaultdict(list)
    for region in regions:
        row, pid = region['record'], region['pid']
        destination = None
        disasm = row.get('Disasm', '')
        direct = re.search(r'^\s*0x[0-9a-f]+:\s*jmp\s+(0x[0-9a-f]+)\s*$', disasm, re.I | re.M)
        if direct:
            destination = int(direct[1], 16)
        # x64 FF 25 00 00 00 00: target is the next eight bytes, not disassembly of data.
        first = next((line for line in row.get('Hexdump','').splitlines() if line.strip()), '')
        octets = re.findall(r'(?<!\S)[0-9a-fA-F]{2}(?=\s)', first)
        if len(octets) >= 14 and ' '.join(octets[:6]).lower() == 'ff 25 00 00 00 00':
            destination = int.from_bytes(bytes.fromhex(''.join(octets[6:14])), 'little')
        targets = [m for m in modules.get(pid, []) if destination is not None and m[0] <= destination < m[1]]
        region['jump_target'] = hex(destination) if destination is not None else ''
        module_path = targets[0][2].get('Path', '').strip() if len(targets) == 1 else ''
        region['target_module'] = module_path if module_path not in EMPTY else ''
        region['target_reference'] = targets[0][3] if len(targets)==1 else {}
        region['context'] = (
            'Jump destination maps to a named recovered module; file signature is not verified.'
            if region['target_module'] else
            'Jump destination falls in a recovered module range, but its path is unavailable; identity is unresolved.'
            if len(targets) == 1 else 'No single destination module was established.'
        )
        groups[(pid, region['process'])].append(region)
    for (pid, name), group in groups.items():
        mapped = sum(bool(g['target_module']) for g in group)
        missing = not modules.get(pid)
        findings.append({'priority':'Review','category':'Executable memory','title':f'Candidate executable regions: {name} (PID {pid})',
            'pid':pid,'process':name,'all_jumps_mapped':mapped==len(group),'status':'Unresolved memory candidates','confidence':'Heuristic candidates; not confirmed injection',
            'observation':f'{len(group)} malfind regions. {mapped} exported jump targets map into named recovered modules.',
            'context':('No DLL inventory was recovered for this PID. ' if missing else '') + 'Full region addresses, protections and jump context are in malfind-regions.csv.',
            'interpretation':'Runtime-generated code and instrumentation can resemble injection. A mapped module name is not a signature check or a benign verdict.',
            'action':'Inspect each candidate in process context, inspect memory bytes and compare mapped module provenance. Use approved rules when available.',
            'references':[{k:g[k] for k in ('plugin','run_id','row_id')} for g in group]})
    if malformed:
        findings.append({'priority':'Medium','category':'Data quality','title':'Questionable process structures require review',
            'pid':None,'process':'','status':'Quality limitation','confidence':'Invalid/implausible fields observed',
            'observation':f'{len(malformed)} flagged rows across the selected successful process plugins; {invalid_pslist} pslist rows excluded from the plausible-object metric.',
            'context':'Raw records are retained unchanged. Counts overlap across process plugins; this is not a count of distinct damaged objects.',
            'interpretation':'Corruption, acquisition inconsistency or interpretation problems are possible. These checks do not establish tampering or a rootkit.',
            'action':'Compare the original CLI output, symbols and capture quality before relying on process totals or cross-view discrepancies.',
            'references':[{k:g[k] for k in ('plugin','run_id','row_id')} for g in malformed]})
    network_rows = network_context(network, capture)
    findings.extend(remote_findings(remote_items,network,process_by_pid))
    findings.extend(port_findings(network_rows))
    process_inventory, process_findings = review_processes(process_by_pid, execution_rows, system_root, case.metadata.get('evidence_os'))
    findings.extend(process_findings)
    binaries, hash_findings, binary_issues = artifact_inventory(case, case.runs(), cancel)
    findings.extend(hash_findings)
    events, event_sources, event_issues = event_timeline(case)
    for process in process_inventory:
        associations=[b for b in binaries if b.get('pid')==process['pid'] and b.get('sha256')]
        if associations and process['identity_status'].startswith('Ambiguous'):
            process['hash_status']='Collected bytes share PID but identity is ambiguous; inspect Files & SHA-256'
            associations=[]
        if associations:
            process['hash_status']='Collected bytes; representation and PID association must be reviewed'
            process['hashes']=[{'sha256':b['sha256'],'representation':b['representation'],'case_path':b['case_path'],'association':b['association']} for b in associations]
    for finding in findings:
        finding['layer']='Context' if (finding['category'] in ('Remote access','Remote-service ports') or finding.get('all_jumps_mapped')) else 'Data quality' if finding['category']=='Data quality' else 'Finding'
    # Keep source-linked context, but do not inflate the actionable count/graphs.
    actionable=[f for f in findings if f['layer']=='Finding']
    context_findings=[f for f in findings if f['layer']=='Context']
    timeline=memory_timeline(process_by_pid, network_rows)

    findings.sort(key=lambda x:(PRIORITY[x['priority']],x['category'],x['title']))
    for i, finding in enumerate(findings, 1):
        finding['id'] = f'F-{i:03d}'
        # Deduplicate provenance, never the original records.
        finding['references'] = list({(r['run_id'],r['row_id']):r for r in finding['references']}.values())
    return {'analysis_logic':'evidence-led', 'findings':findings,'finding_priorities':dict(Counter(f['priority'] for f in actionable)),
            'finding_categories':dict(Counter(f['category'] for f in actionable)),
            'actionable_count':len(actionable), 'context_count':len(context_findings),
            'suppressed_records':suppressed, 'suppression_counts':dict(Counter(x['reason'] for x in suppressed)),
            'process_inventory':process_inventory,'binary_evidence':binaries,'binary_issues':binary_issues,
            'memory_timeline':timeline,'event_timeline':events,'event_sources':event_sources,'event_issues':event_issues,
            'quality_flags':malformed,'plausible_process_objects':len(valid_pslist),
            'plausible_process_pids':len(process_seen),'excluded_pslist_rows':invalid_pslist,
            'malfind_regions':regions,'malfind_groups':[(f'{name} / PID {pid}',len(g)) for (pid,name),g in sorted(groups.items(), key=lambda i:len(i[1]),reverse=True)],
            'network_records':network, 'network_context':network_rows, 'remote_access_records':remote_items,
            'script_references':script_matches, 'script_match_count':len(script_matches),
            'keyword_matches':keyword_matches,'capture_time_utc':capture.isoformat() if capture else None,
            'finding_limits':'Automated rules are intentionally conservative and incomplete. Priorities are review order, not severity or proof of compromise. No online reputation lookup or signature verification is performed. Supplied hash-intelligence matches are labeled with their source and byte representation. No automatic human attribution or authorization verdict.'}
