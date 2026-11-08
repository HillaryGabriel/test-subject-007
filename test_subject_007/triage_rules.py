"""Field-aware triage rules. Path/behavior anomalies are not malware verdicts.

Read only semantic fields; configuration values and filenames are not execution.
The caller keeps original rows and an auditable context/suppression ledger.
"""
from __future__ import annotations
import ntpath
import re

SCRIPT_EXT = r'(?:ps1|psm1|vbs|vbe|wsf|wsh|hta|js|jse|jar|py|sh|bat|cmd)'
SCRIPT_FILE = re.compile(r'\.' + SCRIPT_EXT + r'(?:$|[\s"\'])', re.I)
INTERPRETERS = {'java','javaw','powershell','pwsh','wscript','cscript','mshta','cmd','bash','sh','dash','python','python3','node','nodejs'}
PROCESS = ('.cmdline.', '.pstree.', '.psaux.', '.pslist.', '.psscan.')
COMMAND = ('.cmdline.', '.pstree.', '.psaux.', '.bash.', '.cmdscan.', '.consoles.')
EXPECTED = {
    'lsass.exe': ('system32',), 'services.exe': ('system32',), 'wininit.exe': ('system32',),
    'winlogon.exe': ('system32',), 'smss.exe': ('system32',), 'csrss.exe': ('system32',),
    'svchost.exe': ('system32','syswow64'), 'spoolsv.exe': ('system32',),
    'explorer.exe': ('',),
}
MIMICS = {'svch0st.exe':'svchost.exe','scvhost.exe':'svchost.exe','svhost.exe':'svchost.exe',
          'lssas.exe':'lsass.exe','lsasss.exe':'lsass.exe','winIogon.exe'.casefold():'winlogon.exe'}


def first_token(command):
    value = str(command or '').strip()
    if value.startswith('"'):
        return value.split('"', 2)[1] if '"' in value[1:] else ''
    # Unquoted Windows executable paths may contain spaces. End at .exe only
    # when the value starts as an absolute Windows path.
    if re.match(r'^(?:[A-Za-z]:\\|\\\\|\\Device\\|\\SystemRoot\\)', value, re.I):
        match = re.match(r'^(.+?\.(?:exe|com|scr))(?=\s|$)', value, re.I)
        if match:
            return match[1]
    match = re.match(r'^(\S+)', value)
    return match[1] if match else ''


def command_text(row):
    for key in ('Args','ARGS','Cmd','CommandLine','Command','Command line','Binary','BinaryPath','Binary (Registry)'):
        value = str(row.get(key, '')).strip()
        if value not in ('', '-', "'-", 'N/A', 'None'):
            return value
    return ''


def basename(path):
    return ntpath.basename(str(path).replace('/', '\\')).casefold()


def primary_path(row):
    for key in ('Path','Audit','FullPath','ImagePathName'):
        value = str(row.get(key, '')).strip().strip('"')
        if value not in ('','-',"'-",'N/A') and re.search(r'\.(exe|com|scr)$',value,re.I):
            return value
    return first_token(command_text(row))


def risky_location(path):
    return bool(re.search(r'\\(?:temp|downloads|users\\public)\\|\\appdata\\(?:local\\temp|roaming)\\', str(path), re.I)
                or re.search(r'''(?:^|[\s"'])\\\\''', str(path)) or re.search(r'''(?:^|[\s"'])/(?:tmp|var/tmp|dev/shm)/''', str(path)))


def script_evidence(plugin, row):
    """Return (context, exclusion). Only actual behavior later becomes a finding."""
    text = '\n'.join(str(v) for v in row.values())
    if '.envars.' in plugin:
        if str(row.get('Variable','')).upper() in ('PATHEXT','PATH','PSMODULEPATH','JAVA_HOME','JRE_HOME','CLASSPATH'):
            return None, 'Environment configuration is not script execution'
        if SCRIPT_FILE.search(text) or re.search(r'\b(?:java|powershell|wscript)\b',text,re.I):
            return None, 'Environment string only; no execution semantics'
        return None, None
    if any(k in plugin for k in PROCESS + ('.svcscan.','.svclist.')):
        command = command_text(row)
        token = first_token(command) or str(row.get('Process',row.get('ImageFileName',row.get('COMM',''))))
        interp = basename(token).removesuffix('.exe')
        if interp in INTERPRETERS:
            kind = 'Interpreter process/command' if any(k in plugin for k in PROCESS) else 'Configured service command'
            return {'kind':kind, 'interpreter':interp, 'command':command,
                    'meaning':'Interpreter invocation observed; script content, completion and intent are unverified.'}, None
        # Do not call notepad.exe readme.vbs an executed script.
        if SCRIPT_FILE.search(command) or re.search(r'(?i)\b(?:powershell|java)\b',text):
            return None, 'Text/argument/display name without an interpreter invocation'
    if '.bash.' in plugin:
        command = command_text(row)
        if command:
            return {'kind':'Shell history command','interpreter':'shell','command':command,
                    'meaning':'Recovered shell history; execution success is unverified.'}, None
    if '.printkey.' in plugin:
        key = str(row.get('Key',row.get('KeyPath','')))
        data = str(row.get('Data',row.get('Value','')))
        interp = basename(first_token(data)).removesuffix('.exe')
        if re.search(r'\\run(?:once)?$',key,re.I) and interp in INTERPRETERS:
            return {'kind':'Configured autostart command','interpreter':interp,'command':data,
                    'meaning':'Registry configuration, not proof of execution.'}, None
    if any(k in plugin for k in ('.filescan.','.handles.','.lsof.')):
        value = str(row.get('Name',row.get('Path','')))
        if value.casefold().endswith(('.evtx','.etl','.dll','.mui')) or '\\winevt\\logs\\' in value.casefold():
            if 'powershell' in value.casefold() or 'script' in value.casefold():
                return None, 'Log/library reference is not script execution'
            return None, None
        if SCRIPT_FILE.search(value):
            return {'kind':'File reference','interpreter':'','command':value,
                    'meaning':'File reference only; does not establish invocation.'}, None
    return None, None


def execution_signals(plugin, row):
    """Concrete suspicious invocation patterns; normal Java remains context."""
    context, _ = script_evidence(plugin,row)
    if not context or context['kind'] not in ('Interpreter process/command','Shell history command','Configured service command','Configured autostart command'):
        return []
    command, interp = context['command'], context['interpreter']
    signals = []
    if interp in ('powershell','pwsh'):
        if re.search(r'(?:^|\s)-(?:e|en|enc|encodedcommand)\s+\S+',command,re.I):
            signals.append(('Encoded PowerShell command','Medium','Encoded argument; decoding and script-content validation required.'))
        download = re.search(r'(?i)\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|wget|curl)\b',command)
        execute = re.search(r'(?i)\b(?:iex|invoke-expression|start-process)\b',command)
        if download and execute:
            signals.append(('Download-and-execute command pattern','High','Download and execution tokens occur in the same interpreter command; successful execution is not proved.'))
    if interp in ('wscript','cscript') and SCRIPT_FILE.search(command) and risky_location(command):
        signals.append(('Script invocation from an exposed location','Medium','An interpreter references a script in a temporary, roaming, public, download or network-share location.'))
    if interp in ('java','javaw') and re.search(r'(?:^|\s)-jar\s+',command,re.I) and risky_location(command):
        signals.append(('JAR invocation from an exposed location','Medium','Java is not malicious by itself; verify this JAR source and the execution chain.'))
    if interp=='mshta' and re.search(r'https?://|javascript:|vbscript:',command,re.I):
        signals.append(('MSHTA remote or inline content','High','The primary interpreter references remote or inline executable content; verify content and authorization.'))
    if interp in ('shell','bash','sh','dash') and re.search(r'\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:ba)?sh\b',command,re.I):
        signals.append(('Download piped to shell','High','A recovered shell command pipes downloaded output into a shell; completion is unverified.'))
    return signals


def windows_path_assessment(path, system_root=r'C:\Windows'):
    """Compare captured Windows strings; never resolve them on the analyst host."""
    path = str(path).strip().strip('"').replace('/','\\')
    root = str(system_root or r'C:\Windows').replace('/','\\').rstrip('\\')
    p = path.casefold()
    if p.startswith('\\??\\'):
        p = p[4:]
    if p.startswith('\\systemroot\\'):
        p = root.casefold() + p[len('\\systemroot'):]
    if p.startswith('%systemroot%') or p.startswith('%windir%'):
        p = re.sub(r'^%(?:systemroot|windir)%',lambda _:root.casefold(),p)
    name = basename(p)
    if name in MIMICS:
        return 'Name resembles '+MIMICS[name]+'; verify identity and provenance'
    if name not in EXPECTED:
        return ''
    if not ('\\' in p):
        return ''  # A bare process name cannot establish location.
    roots=[root.casefold()]
    device = re.match(r'^(\\device\\harddiskvolume\d+)(\\.*)$',p,re.I)
    if device:
        # The captured volume is not mapped to an analyst drive; compare the
        # OS-directory suffix only and never invent a C: mapping.
        roots=[device[1]+'\\'+ntpath.basename(root).casefold()]
    if not (re.match(r'^[a-z]:\\',p) or p.startswith('\\device\\') or p.startswith('\\\\')):
        return ''
    expected=[ntpath.normpath(r+'\\'+d+'\\'+name).casefold() for r in roots for d in EXPECTED[name]]
    if ntpath.normpath(p) in expected:
        return ''
    return 'System executable name outside its expected OS location: '+', '.join(expected)
