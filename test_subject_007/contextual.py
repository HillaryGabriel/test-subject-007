"""Field-aware observable labels. Pattern matches never imply maliciousness."""
from __future__ import annotations
import re
from urllib.parse import urlsplit

NETWORK_FIELDS = {'localaddr','foreignaddr','remoteaddr','localaddress','foreignaddress','remoteaddress','srcaddr','dstaddr','source ip','destination ip','source addr','destination addr'}


def contextual_matches(row, plugin, extractor):
    accepted, excluded = {}, []
    for field, raw in row.items():
        text = str(raw)
        lower = text.casefold()
        # Structured numeric/process fields are not textual IOC sources.
        if field.casefold() in {'pid','ppid','base','size','offset(v)','offset','treedepth','threads','handles','sessionid','start vpn','end vpn','disasm','hexdump'}:
            continue
        for start in range(0, len(text), 60000):
            for kind, value, note in extractor(text[start:start+62048]):
                normalized = value.casefold()
                before = lower.find(normalized)
                left = lower[:before] if before >= 0 else ''
                right = lower[before+len(value):] if before >= 0 else ''
                path_component = left.endswith('\\') and right.startswith('\\')
                local_path = (re.match(r'^[a-z]:\\', text, re.I) or text.startswith('\\Device\\') or text.startswith('file:'))
                reason = ''
                if kind == 'IP address':
                    if path_component and not left.endswith('\\\\'):
                        reason = 'Dotted numeric directory component, not an observed network endpoint'
                    elif re.search(r'\\\\' + re.escape(value) + r'\\', text, re.I):
                        kind, note = 'Network share address', 'UNC-path reference; not proof of a successful network session'
                    elif field.casefold() in NETWORK_FIELDS:
                        kind, note = 'Network endpoint', 'Recovered network-object field; validate the owning process and connection state'
                    elif 'user-agent' in lower and value in re.findall(r'(?<![\d.])(?:\d+\.){3}\d+(?![\d.])', text):
                        reason = 'Version-like string in User-Agent text; not a network endpoint'
                    else:
                        kind, note = 'IP address candidate', 'Literal text only; network activity not established'
                elif kind == 'Domain candidate' and (path_component or local_path):
                    reason = 'Local path component, not evidence of a contacted domain'
                elif kind == 'Hash candidate':
                    if '/pfhostedapp:' + normalized in lower:
                        kind, note = 'Identifier candidate', 'Browser/WebView command argument; not a computed file hash'
                    elif 'symbols' in lower and '.pdb' in lower:
                        kind, note = 'Symbol identifier', 'PDB/symbol-path identifier; not a computed file hash'
                    elif path_component or ('nativeimages_' in lower):
                        kind, note = 'Identifier candidate', 'Hexadecimal path component; not a computed file hash'
                    else:
                        kind, note = 'Hash-shaped string', 'Pattern match only; source file and hash algorithm unverified'
                elif kind == 'URL':
                    note = 'URL in recovered text; no DNS lookup or connection performed'
                if reason:
                    excluded.append({'field':field,'value':value,'reason':reason,'context':text})
                else:
                    accepted[(kind, value)] = note + ' / field: ' + field
    return [(k,v,n) for (k,v),n in accepted.items()], excluded
