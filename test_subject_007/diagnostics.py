"""Preserve error evidence and explain failures without inventing a cause."""
from __future__ import annotations
import re
from pathlib import Path
from .util import tail_text


def collect_log(folder: Path, limit=80000) -> str:
    parts = []
    for name in ('stderr.log', 'stdout.csv', 'volatility.log'):
        text = tail_text(folder / name, limit)
        if text.strip():
            parts.append('=== ' + name + ' ===\n' + text)
    return '\n\n'.join(parts) or 'No engine output was recorded.'


def diagnose(run: dict, folder: Path | None = None, text: str = '') -> dict:
    if folder is not None:
        text = collect_log(folder)
    text += '\n' + str(run.get('error', ''))
    low = text.casefold()
    status = run.get('status', 'unknown')
    requirements = list(dict.fromkeys(re.findall(r'Unsatisfied requirement\s+([^:\s]+)', text)))
    details = []
    for line in text.splitlines():
        if re.search(r'unsatisfied requirement|unable to validate|error:|exception:|permission denied|no such file|modulenotfounderror|sslerror|certificate_verify_failed', line, re.I):
            if line.strip() not in details:
                details.append(line.strip()[:1000])
    title, code, actions = 'Analysis did not complete', 'engine_failure', []
    if status in ('completed', 'completed_with_warnings') and not run.get('index_error'):
        title = 'Analysis completed' if status == 'completed' else 'Analysis completed with warnings'
        code = 'completed'
        actions = ['Review recovered artifacts in context. Empty results do not establish that the system was clean.']
    elif requirements or 'unable to validate the plugin requirements' in low:
        title, code = 'Volatility could not satisfy the image / symbol requirements', 'requirements'
        actions = [
            'Check the selected file is a supported system-memory capture, not a process minidump, archive, or disk image.',
            'Select the captured operating system, not the operating system of this workstation.',
            'For Windows: enable symbol downloads only if permitted, or supply matching symbols in Settings.',
            'For Linux: supply an ISF whose kernel banner exactly matches the capture.',
            'Retry analysis after addressing the logged requirement. These messages alone cannot distinguish missing symbols from an unsupported or damaged capture.'
        ]
        if run.get('offline'):
            actions.insert(0, 'This run used offline symbols. Missing symbols could not be downloaded.')
    elif 'no module named' in low or 'missing analysis dependency' in low:
        title, code = 'An analysis dependency is missing', 'dependency'
        actions = ['Run the installer from this application folder using the same virtual environment as the launcher.',
                   'Review --doctor and the missing module named below.']
    elif any(token in low for token in ('certificate_verify_failed', 'sslerror', 'temporary failure in name resolution', 'getaddrinfo failed')):
        title, code = 'Symbol-server connectivity failed', 'network'
        actions = ['Check approved proxy/DNS/CA settings or provision trusted matching symbols offline.',
                   'Do not disable TLS certificate verification to bypass this error.']
    elif 'permission denied' in low or 'permissionerror' in low:
        title, code = 'A file or directory is not accessible', 'permission'
        actions = ['Check read permission for the image and write permission for case/output folders.',
                   'Use a normal account with appropriate access; do not change original evidence permissions unnecessarily.']
    elif status in ('cancelled', 'timed_out', 'interrupted'):
        title, code = 'Analysis was ' + status.replace('_', ' '), status
        actions = ['Results may be incomplete. Review the logs, adjust the timeout if needed, and rerun.']
    elif status == 'integrity_warning':
        title, code = 'Evidence integrity requires attention', 'integrity'
        actions = ['Stop interpreting these results and verify the source SHA-256 against the import record.']
    elif run.get('index_error'):
        title, code = 'No complete result table was produced', 'renderer'
        actions = ['Read both stdout and stderr below. Raw engine output has been preserved.',
                   'A missing CSV table is not a finding of zero threats.']
    if not actions:
        actions = ['Read the engine messages below and correct the reported issue before retrying.',
                   'A failed run cannot support a conclusion that the memory image is clean.']
    return {'code': code, 'title': title, 'requirements': requirements, 'messages': details[:20],
            'actions': actions, 'status': status}


def format_diagnosis(value: dict) -> str:
    return (value['title'] + '\n\n' + '\n'.join('- ' + s for s in value['actions']) +
            ('\n\nENGINE MESSAGES\n' + '\n'.join(value['messages']) if value['messages'] else ''))
