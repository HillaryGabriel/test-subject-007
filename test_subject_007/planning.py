"""Deterministic per-plugin preflight: keep ready jobs, enumerate every blocker."""
from __future__ import annotations
from dataclasses import dataclass, field
from .options import validate_options
from .profiles import default_jobs

ORDER = {'windows.info': 0, 'banners': 0, 'linux.pslist': 1, 'mac.pslist': 1,
         'windows.pslist': 1, 'windows.pstree': 2, 'windows.psscan': 3, 'windows.cmdline': 4}
SENSITIVE = {'hashdump', 'cachedump', 'lsadump'}


@dataclass
class Plan:
    selected: list[str] = field(default_factory=list)
    items: list = field(default_factory=list)
    deferred: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    @property
    def ready_plugins(self):
        return {plugin['name'] for plugin, args in self.items}

    def record(self):
        return {'selected_plugins': self.selected,
                'ready_jobs': [{'plugin': p['name'], 'arguments': a} for p, a in self.items],
                'deferred': self.deferred, 'unavailable': self.missing, 'notices': self.notices}


def build_plan(catalog, selected, saved, profile, evidence_os, missing=(), check_files=True):
    plugins = {p['name']: p for p in catalog.get('plugins', [])}
    plan = Plan(selected=sorted(set(selected), key=lambda n: (ORDER.get(n.rsplit('.', 1)[0], 10), n)),
                missing=list(missing))
    for name in plan.selected:
        p = plugins.get(name)
        if p is None:
            plan.deferred.append({'plugin': name, 'reason': 'Plugin is no longer in the installed catalog.', 'status': 'Needs configuration', 'job': 1})
            continue
        family = {'Windows': 'windows', 'Linux': 'linux', 'macOS': 'mac'}.get(evidence_os)
        if family and name.split('.')[0] in ('windows', 'linux', 'mac') and not name.startswith(family + '.'):
            plan.deferred.append({'plugin': name, 'reason': 'Plugin OS does not match the captured OS: ' + evidence_os, 'status': 'OS mismatch', 'job': 1})
            continue
        jobs = [saved[name]] if name in saved else default_jobs(p, profile, evidence_os)
        for index, values in enumerate(jobs, 1):
            argv, problems = validate_options(p, values, check_files=check_files)
            if problems:
                plan.deferred.append({'plugin': name, 'reason': '; '.join(problems), 'status': 'Needs configuration', 'job': index})
            else:
                plan.items.append((p, argv))
        if name.split('.')[-2] in SENSITIVE:
            plan.notices.append(name + ': credential material may be recovered; limit distribution of outputs.')
    if len(plan.items) > 30:
        plan.notices.append('Broad plan: individual scans can be lengthy and produce large outputs. Engine completion does not imply exhaustive coverage.')
    return plan
