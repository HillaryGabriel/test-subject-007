"""Targeted review helpers. These classify evidence context, not intent or guilt."""
from __future__ import annotations
from collections import defaultdict, Counter
import ipaddress
import re
from .chronology import timestamp

# Match executable tokens, not arbitrary DLL/path substrings or prose tool names.
TOOLS = {
 'anydesk.exe':'AnyDesk', 'anydesk':'AnyDesk', 'teamviewer.exe':'TeamViewer',
 'teamviewer_service.exe':'TeamViewer', 'rustdesk.exe':'RustDesk', 'rustdesk':'RustDesk',
 'screenconnect.clientservice.exe':'ScreenConnect', 'screenconnect.windowsclient.exe':'ScreenConnect',
 'tvnserver.exe':'TightVNC', 'winvnc.exe':'VNC', 'vncserver':'VNC', 'x11vnc':'VNC',
 'meshagent.exe':'MeshCentral', 'meshagent':'MeshCentral', 'dwagent.exe':'DWService',
 'srservice.exe':'Splashtop', 'srserver.exe':'Splashtop', 'remotepcservice.exe':'RemotePC',
 'quickassist.exe':'Quick Assist', 'mstsc.exe':'RDP client', 'msrdc.exe':'Remote Desktop client',
 'sshd.exe':'SSH server', 'sshd':'SSH server', 'ssh.exe':'SSH client', 'ssh':'SSH client',
 'psexesvc.exe':'Remote-service execution', 'remcomsvc.exe':'Remote-service execution',
 'wsmprovhost.exe':'Windows Remote Management provider',
}
TOOL_PATTERN = re.compile(r'(?<![A-Za-z0-9_.-])('+ '|'.join(re.escape(s) for s in sorted(TOOLS,key=len,reverse=True)) +r')(?![A-Za-z0-9_.-])',re.I)
REMOTE_PORTS={'22':'SSH','3389':'RDP','5900':'VNC','5901':'VNC','5985':'WinRM','5986':'WinRM TLS'}
PROCESS_PLUGINS=('.cmdline.','.psaux.','.pstree.','.pslist.','.psscan.','.svcscan.','.svclist.')
SEARCH_PLUGINS=PROCESS_PLUGINS+('.filescan.','.handles.','.printkey.','.bash.','.lsof.','.userassist.','.amcache.','.cmdscan.','.consoles.','.scheduled_tasks.','.envars.')


def token_match(term, row):
    """IPs/domains/hashes use boundaries; normal terms stay literal. No lookups."""
    term=term.strip().casefold()
    if not term:return False
    text='\n'.join(str(v) for k,v in row.items() if k not in ('TreeDepth','Hexdump','Disasm'))
    try:
        address=ipaddress.ip_address(term)
        # A colon can introduce a port after an IPv4 address or bracketed IPv6.
        # Keep boundaries tight enough not to match a prefix of a longer address.
        if address.version == 4:
            pattern = r'(?<![\w.])'+re.escape(term)+r'(?![\w.])'
        else:
            pattern = r'(?<![0-9a-f:])'+re.escape(term)+r'(?![0-9a-f:])'
        for value in row.values():
            value=str(value)
            # Numeric component between single path separators is not an endpoint.
            if re.search(r'(?<!\\)\\'+re.escape(term)+r'\\',value,re.I):
                continue
            if re.search(pattern,value,re.I):return True
        return False
    except ValueError:
        pass
    if re.fullmatch(r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}',term):
        return bool(re.search(r'(?<![0-9a-z])'+re.escape(term)+r'(?![0-9a-z])',text,re.I))
    if re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,63}',term) and not term.endswith(('.exe','.dll','.vbs','.ps1','.jar','.js','.hta','.wsf','.bat','.cmd','.sh','.py')):
        return bool(re.search(r'(?<![a-z0-9_.-])'+re.escape(term)+r'(?![a-z0-9_.-])',text,re.I))
    return term in text.casefold()


def remote_matches(plugin, row):
    fields=('Process','ImageFileName','COMM','Args','ARGS','Cmd','Command','CommandLine','Binary','BinaryPath','Path')
    if not any(p in plugin for p in PROCESS_PLUGINS):return []
    values=[]
    for field in fields:
        value=str(row.get(field,''))
        if field in ('Args','ARGS','Cmd','Command','CommandLine','Binary','BinaryPath'):
            match=re.match(r'^\s*(?:"([^"\r\n]+)"|(\S+))',value)
            value=(match[1] or match[2]) if match else ''
        values.append(value)
    hay='\n'.join(values)
    result={TOOLS[m.group().casefold()] for m in TOOL_PATTERN.finditer(hay)}
    cmd=str(row.get('Args',row.get('ARGS',row.get('Cmd',''))))
    if re.search(r'\bsvchost\.exe\b',hay,re.I):
        if re.search(r'(?:^|\s)-s\s+TermService(?:\s|$)',cmd,re.I):result.add('RDP service host')
        if re.search(r'(?:^|\s)-s\s+WinRM(?:\s|$)',cmd,re.I):result.add('WinRM service host')
    return sorted(result)



def remote_findings(items, network, process_by_pid):
    groups=defaultdict(list)
    for entry in items:groups[(entry['tool'],entry['pid'])].append(entry)
    out=[]
    for (tool,pid),group in groups.items():
        related=process_by_pid.get(pid,[])
        identities={r.get('Offset(V)',r.get('Offset','')) for _,r in related if r.get('Offset(V)',r.get('Offset',''))}
        ambiguous=len(identities)>1
        sockets=[] if ambiguous or pid is None else [r for r in network if str(r['record'].get('PID'))==str(pid)]
        first=group[0]['record']
        name=first.get('Process',first.get('ImageFileName',first.get('COMM','')))
        observation='\n'.join(k+': '+str(v) for k,v in first.items() if v and k!='TreeDepth')
        context=f'{len(group)} matching process/service records. '
        context+=('Multiple process identities share this PID; network correlation withheld.' if ambiguous else
                  f'{len(sockets)} recovered network-object rows share this PID; PID correlation alone does not prove common lifetime or successful access.')
        out.append({'priority':'Review','category':'Remote access','title':f'{tool} executable reference'+(f' (PID {pid})' if pid is not None else ''),
            'pid':pid,'process':name,'status':'Authorization not established','confidence':'Executable token observed; identity/signature unverified',
            'observation':observation,'context':context,
            'interpretation':'Remote-administration tools can be approved. A process, service, or matching port is not proof of unauthorized control, a successful session, or the identity of an operator.',
            'action':'Validate installation approval, executable signature and provenance. Correlate logon/session, EDR and remote-tool logs at the capture time; preserve evidence before changes.',
            'references':[x['reference'] for x in group]+[{k:r[k] for k in ('plugin','run_id','row_id')} for r in sockets]})
    return out


def network_context(network, capture=None):
    """Retain each source row; no dedup that obscures per-plugin observations."""
    values=[]
    for item in network:
        r=item['record']
        local=str(r.get('LocalAddr',r.get('LocalAddress',r.get('Source Addr',''))))
        remote=str(r.get('ForeignAddr',r.get('RemoteAddr',r.get('ForeignAddress',r.get('Destination Addr','')))))
        lp=str(r.get('LocalPort',r.get('Source Port','')));rp=str(r.get('ForeignPort',r.get('RemotePort',r.get('Destination Port',''))))
        hint=[]
        if lp in REMOTE_PORTS:hint.append(REMOTE_PORTS[lp]+' conventional local port')
        if rp in REMOTE_PORTS:hint.append(REMOTE_PORTS[rp]+' conventional remote port')
        time_field=next((k for k in ('Created','CreateTime','Create Time') if k in r),'')
        times=timestamp(r.get(time_field,''),assume_utc=True,capture=capture)
        values.append({**item,**times,'timestamp_field':time_field,'timestamp_kind':'Network-object creation; not logon time','pid':r.get('PID',r.get('Pid','')),'owner':r.get('Owner',r.get('Process',r.get('Process Name',r.get('COMM','')))),
            'local_address':local,'local_port':lp,'remote_address':remote,'remote_port':rp,
            'state':r.get('State',''),'protocol':r.get('Proto',r.get('Protocol','')),
            'port_context':'; '.join(hint),'interpretation':'Recovered object only; ports do not authenticate services or establish authorization.'})
    return values


def port_findings(network):
    grouped=defaultdict(list)
    for entry in network:
        if entry['port_context']:grouped[entry['port_context']].append(entry)
    out=[]
    for hint,items in grouped.items():
        first=items[0]
        out.append({'priority':'Informational','category':'Remote-service ports','title':hint,
            'pid':None,'process':'','status':'Context only','confidence':'Port value observed; protocol inferred, not verified',
            'observation':f"{len(items)} recovered network rows. Example: {first['local_address']}:{first['local_port']} -> {first['remote_address']}:{first['remote_port']} / {first['state']}",
            'context':'Full rows, owners, state and source references are in network-context.csv. Counts can overlap across plugins.',
            'interpretation':'A conventional port number is not proof of its application protocol, an active remote session, or malicious access.',
            'action':'Correlate the owner, direction and state with firewall, authentication and endpoint records; validate authorized administration.',
            'references':[{k:x[k] for k in ('plugin','run_id','row_id')} for x in items]})
    return out
