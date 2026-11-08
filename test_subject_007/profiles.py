"""Investigation starting points, resolved against the installed engine catalog.

Profiles are explicit scopes, never claims of exhaustive malware detection.
No credential extraction is selected automatically. Advanced options remain available.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Job:
    candidate: str
    values: dict = field(default_factory=dict)

COMMON = ['windows.info', 'windows.pslist', 'windows.pstree', 'windows.psscan', 'windows.cmdline']
MALFIND = 'windows.malware.malfind|windows.malfind'
LDR = 'windows.malware.ldrmodules|windows.ldrmodules'
RUN_KEYS = [
    r'Software\Microsoft\Windows\CurrentVersion\Run',
    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'Microsoft\Windows\CurrentVersion\Run',
    r'Microsoft\Windows\CurrentVersion\RunOnce',
]
# Curated read-only survey. External rules, selected offsets, bulk extraction,
# credentials and developer utilities are deliberately not auto-selected.
COMPLETE = 'Complete forensic investigation'
COMPLETE_WINDOWS = COMMON + [
    'windows.crashinfo', 'windows.envars', 'windows.getsids', 'windows.privileges',
    'windows.sessions', 'windows.cmdscan', 'windows.consoles', 'windows.dlllist',
    MALFIND, LDR, 'windows.malware.psxview|windows.psxview',
    'windows.malware.hollowprocesses|windows.hollowprocesses',
    'windows.malware.suspicious_threads|windows.suspicious_threads',
    'windows.malware.processghosting|windows.processghosting',
    'windows.vadinfo', 'windows.vadtree', 'windows.memmap', 'windows.handles',
    'windows.filescan', 'windows.mftscan.MFTScan', 'windows.netscan', 'windows.netstat',
    'windows.svcscan', 'windows.svclist', 'windows.modules', 'windows.modscan',
    'windows.driverscan', 'windows.driverirp', 'windows.unloadedmodules',
    'windows.callbacks', 'windows.ssdt', 'windows.symlinkscan', 'windows.mutantscan',
    'windows.joblinks', 'windows.threads', 'windows.thrdscan', 'windows.timers',
    'windows.registry.hivelist', 'windows.registry.hivescan',
    'windows.registry.printkey', 'windows.registry.userassist',
    'windows.registry.amcache', 'windows.registry.scheduled_tasks',
    'windows.shimcachemem', 'windows.verinfo',
]
COMPLETE_LINUX = [
    'banners', 'linux.pslist', 'linux.pstree', 'linux.psscan', 'linux.psaux',
    'linux.envars', 'linux.bash', 'linux.lsof', 'linux.sockstat', 'linux.lsmod',
    'linux.proc.Maps', 'linux.mountinfo', 'linux.capabilities',
    'linux.malware.malfind|linux.malfind',
    'linux.malware.check_modules|linux.check_modules',
    'linux.malware.check_syscall|linux.check_syscall',
    'linux.malware.check_afinfo|linux.check_afinfo',
    'linux.malware.check_creds|linux.check_creds',
    'linux.malware.hidden_modules|linux.hidden_modules',
]
COMPLETE_LIMITS = ('Broad memory survey, not a guarantee of every artifact or technique. '
    'Credential recovery, targeted extraction, PE-symbol lookup, external strings and '
    'analyst-supplied YARA rules are not auto-selected. Configure these in Custom when needed.')
WIN = {
    COMPLETE: COMPLETE_WINDOWS,
    'Quick triage': COMMON + ['windows.netscan', 'windows.dlllist', MALFIND],
    'Malware investigation': COMMON + ['windows.netscan', 'windows.netstat', 'windows.dlllist', MALFIND,
                                    LDR, 'windows.svcscan', 'windows.filescan', 'windows.handles'],
    'Persistence investigation': COMMON + ['windows.dlllist', 'windows.svcscan', 'windows.registry.hivelist',
                                          'windows.registry.printkey', 'windows.filescan'],
    'Network investigation': COMMON + ['windows.netscan', 'windows.netstat', 'windows.handles'],
    'Java and script investigation': COMMON + ['windows.dlllist', 'windows.filescan', 'windows.handles',
                                              'windows.svcscan', 'windows.registry.printkey', MALFIND],
}
LINUX = {
    COMPLETE: COMPLETE_LINUX,
    'Quick triage': ['banners', 'linux.pslist', 'linux.pstree', 'linux.bash', 'linux.lsmod', 'linux.sockstat'],
    'Malware investigation': ['banners', 'linux.pslist', 'linux.pstree', 'linux.psscan', 'linux.bash',
                             'linux.lsmod', 'linux.sockstat', 'linux.malware.malfind|linux.malfind',
                             'linux.malware.check_modules|linux.check_modules'],
    'Persistence investigation': ['banners', 'linux.pslist', 'linux.pstree', 'linux.bash', 'linux.lsmod', 'linux.lsof'],
    'Network investigation': ['banners', 'linux.pslist', 'linux.pstree', 'linux.sockstat', 'linux.lsof'],
    'Java and script investigation': ['banners', 'linux.pslist', 'linux.pstree', 'linux.bash', 'linux.lsof'],
}
DESCRIPTIONS = {
 COMPLETE: COMPLETE_LIMITS,
 'Quick triage': 'A starting view of processes, command lines, modules and network artifacts. Not an exhaustive investigation.',
 'Malware investigation': 'Process, module, candidate injection, file, handle and service coverage. Matches remain review items, not malware verdicts.',
 'Persistence investigation': 'Windows: Startup context, services and four Run/RunOnce queries. Linux: process, shell and module context; not complete persistence coverage.',
 'Network investigation': 'Recover network objects and owning process context. No DNS, reputation lookup or outbound probing is performed.',
 'Java and script investigation': 'Search process, command, file, handle and service output for Java/JAR/script references. Windows includes Run/RunOnce keys. No raw-memory string scan.',
 'Custom': 'Select individual plugins. Configure options on the right and save them before starting.',
}


# Goal-oriented profiles select evidence sources, not pre-decided verdicts.
REMOTE = 'Remote access investigation'
ACTIVITY = 'User activity investigation'
KERNEL = 'Kernel and rootkit investigation'
WIN.update({
    REMOTE: COMMON + ['windows.netscan', 'windows.netstat', 'windows.sessions',
        'windows.envars', 'windows.getsids', 'windows.svcscan', 'windows.svclist',
        'windows.handles', 'windows.filescan', 'windows.registry.hivelist',
        'windows.registry.printkey'],
    ACTIVITY: COMMON + ['windows.sessions', 'windows.envars', 'windows.getsids',
        'windows.cmdscan', 'windows.consoles', 'windows.handles', 'windows.filescan',
        'windows.registry.hivelist', 'windows.registry.userassist',
        'windows.registry.amcache', 'windows.shimcachemem'],
    KERNEL: COMMON + ['windows.modules', 'windows.modscan', 'windows.driverscan',
        'windows.driverirp', 'windows.unloadedmodules', 'windows.callbacks',
        'windows.ssdt', 'windows.timers', 'windows.malware.psxview|windows.psxview',
        'windows.malware.suspicious_threads|windows.suspicious_threads'],
})
WIN['Java and script investigation'] = COMMON + ['windows.envars', 'windows.dlllist',
    'windows.filescan', 'windows.handles', 'windows.svcscan', 'windows.cmdscan',
    'windows.consoles', 'windows.registry.hivelist', 'windows.registry.printkey',
    'windows.registry.scheduled_tasks', MALFIND]
WIN['Persistence investigation'] += ['windows.registry.scheduled_tasks', 'windows.registry.amcache']
LINUX.update({
    REMOTE: ['banners', 'linux.pslist', 'linux.pstree', 'linux.psaux', 'linux.envars',
             'linux.sockstat', 'linux.lsof', 'linux.bash'],
    ACTIVITY: ['banners', 'linux.pslist', 'linux.pstree', 'linux.psaux', 'linux.envars',
               'linux.bash', 'linux.lsof', 'linux.mountinfo'],
    KERNEL: ['banners', 'linux.pslist', 'linux.psscan', 'linux.lsmod',
        'linux.malware.check_modules|linux.check_modules',
        'linux.malware.hidden_modules|linux.hidden_modules',
        'linux.malware.check_syscall|linux.check_syscall',
        'linux.malware.check_afinfo|linux.check_afinfo'],
})
LINUX['Java and script investigation'] = ['banners', 'linux.pslist', 'linux.pstree',
    'linux.psaux', 'linux.envars', 'linux.bash', 'linux.lsof']
DESCRIPTIONS.update({
    REMOTE: 'Remote-support tools, RDP/SSH/WinRM context, services, sessions and network objects. Tool presence or a listening port does not prove unauthorized access.',
    ACTIVITY: 'Process, session, command and available execution-history artifacts. Memory is not a complete activity timeline and does not identify a human operator.',
    KERNEL: 'Drivers, modules, callbacks and selected cross-view checks. An anomaly is a review lead, not proof of a rootkit.',
    'Java and script investigation': 'Java/JAR, VBS/WSF, PowerShell, JS/HTA and shell references in selected process, command, file, handle and registry outputs. Not a raw-RAM string scan.',
})
REMOTE_KEYS = [
    r'Software\Microsoft\Terminal Server Client\Default',
    r'Software\Microsoft\Terminal Server Client\Servers',
    r'ControlSet001\Control\Terminal Server',
    r'ControlSet002\Control\Terminal Server',
    r'System\CurrentControlSet\Control\Terminal Server',
]
SUSPICIOUS_EXECUTION = 'Suspicious execution investigation'
WIN[SUSPICIOUS_EXECUTION] = WIN['Java and script investigation']
LINUX[SUSPICIOUS_EXECUTION] = LINUX['Java and script investigation']
DESCRIPTIONS.pop('Java and script investigation', None)
DESCRIPTIONS[SUSPICIOUS_EXECUTION] = ('Interpreter invocation, encoded/download-execute patterns, exposed script locations and autostart commands. PATHEXT, service display names and log-file references are context, not execution findings.')
GOALS = [
 {'id':'triage','title':'Incident triage','profile':'Quick triage',
  'question':'Which artifacts need follow-up?', 'detail':'Processes, paths, commands and network baseline.',
  'limit':'Start here for an unknown incident. Review failures and quality flags before drawing conclusions.'},
 {'id':'remote','title':'Remote access & RDP','profile':REMOTE,
  'question':'What remote-access evidence and times are available?', 'detail':'Tooling, network times and imported logon events.',
  'limit':'Memory timestamps are not authentication times. Import host-specific EVTX/XML in Evidence lab for a sourced chronology. Authorization requires separate evidence.'},
 {'id':'network','title':'Network evidence','profile':'Network investigation',
  'question':'Which endpoints, owners and object times were recovered?', 'detail':'Addresses, ports, states, ownership and timestamps.',
  'limit':'Recovered objects can be stale or duplicated. No online reputation lookup; ports alone do not prove protocol or maliciousness.'},
 {'id':'malware','title':'Process integrity','profile':'Malware investigation',
  'question':'Which process identities or executable regions are anomalous?', 'detail':'Paths, parent context, modules and memory regions.',
  'limit':'A curated Windows location baseline flags selected system names. Legitimate applications may live in user profiles. Collect file bytes in Evidence lab for hashes.'},
 {'id':'scripts','title':'Suspicious execution','profile':SUSPICIOUS_EXECUTION,
  'question':'Is there concrete interpreter or command-abuse evidence?', 'detail':'Encoded commands, remote content and risky script launch.',
  'limit':'Normal Java/PowerShell presence is context. File references, PATHEXT and service descriptions do not establish execution. No deobfuscation or complete raw-RAM search.'},
 {'id':'persistence','title':'Persistence','profile':'Persistence investigation',
  'question':'Which recovered artifacts may launch automatically?', 'detail':'Startup executables, services, Run keys and tasks.',
  'limit':'Configured persistence is not proof it executed. Missing memory artifacts do not exclude disk-based persistence.'},
 {'id':'activity','title':'Activity timeline','profile':ACTIVITY,
  'question':'What sequence is supported by the available timestamps?', 'detail':'Process lifetimes and available activity artifacts.',
  'limit':'UTC and PHT are displayed explicitly. Process, network and imported event times have different semantics; missing timestamps stay unavailable.'},
 {'id':'kernel','title':'Kernel integrity','profile':KERNEL,
  'question':'Which kernel/module views need validation?', 'detail':'Drivers, modules, callbacks and cross-view checks.',
  'limit':'Acquisition effects and legitimate hooks can produce differences. No automatic rootkit verdict.'},
 {'id':'complete','title':'Full evidence survey','profile':COMPLETE,
  'question':'Collect the broad curated evidence scope.', 'detail':'Combine process, memory, network and persistence views.',
  'limit':COMPLETE_LIMITS},
]


def goal_details(profile):
    return next((dict(g) for g in GOALS if g['profile'] == profile),
                {'id':'custom','title':'Custom investigation','profile':profile,
                 'question':'Analyst-selected evidence sources',
                 'detail':'Only the selected plugins will be run.',
                 'limit':DESCRIPTIONS.get(profile, DESCRIPTIONS['Custom']), 'effort':'Custom'})


def resolve(catalog, evidence_os, profile):
    if profile == 'Custom':
        return [], []
    definitions = WIN if evidence_os == 'Windows' else LINUX if evidence_os == 'Linux' else {}
    selected, missing = [], []
    if profile not in definitions:
        return [], [profile + ' is not defined for ' + evidence_os]
    for candidate in definitions.get(profile, []):
        match = None
        for prefix in candidate.split('|'):
            match = next((p for p in catalog.get('plugins', []) if p['name'] == prefix or p['name'].rsplit('.', 1)[0] == prefix), None)
            if match:
                break
        if match:
            selected.append(match)
        else:
            missing.append(candidate)
    return selected, missing


def default_jobs(plugin, profile, evidence_os):
    if evidence_os == 'Windows' and profile == REMOTE and '.printkey.' in plugin['name']:
        return [{'key': key} for key in REMOTE_KEYS]
    if evidence_os == 'Windows' and profile in ('Persistence investigation', 'Java and script investigation', SUSPICIOUS_EXECUTION, COMPLETE) and '.printkey.' in plugin['name']:
        return [{'key': key} for key in RUN_KEYS]
    return [{}]


def signature(run):
    """Do not collapse distinct printkey keys or PID-scoped attempts."""
    import json
    return run['plugin'] + ' ' + json.dumps(run.get('arguments', []), separators=(',', ':'))
