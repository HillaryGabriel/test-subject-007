"""Validate analyst-supplied options without importing the Volatility engine.

A missing plugin option is a per-task problem, never a reason to lose the rest
of a batch. Defaults come from the installed catalog; targets are never guessed.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname


class PluginOptionsError(ValueError):
    def __init__(self, plugin, problems):
        self.problems = problems
        name = plugin.get('name', 'Selected plugin')
        super().__init__(name + ': ' + '; '.join(problems))


def _empty(value):
    return value is None or value == [] or (isinstance(value, str) and not value.strip())


def effective_values(plugin, supplied):
    """Use real defaults for empty fields, but preserve False, zero and lists."""
    values = {}
    for spec in plugin.get('options', []):
        value = supplied.get(spec['name'])
        if _empty(value):
            value = spec.get('default')
        values[spec['name']] = value
    return values


def _integer(value):
    if isinstance(value, bool):
        raise ValueError('expected an integer, not a boolean')
    text = str(value).strip()
    # Accept ordinary decimal PIDs with leading zeroes, and explicit 0x offsets.
    return int(text, 0) if text.lower().lstrip('+-').startswith(('0x', '0o', '0b')) else int(text, 10)


def _bool(value):
    if isinstance(value, bool):
        return value
    if value in (None, '', 0, '0', 'false', 'False'):
        return False
    if value in (1, '1', 'true', 'True'):
        return True
    raise ValueError('expected a checkbox value')


def _local_file(value):
    text = str(value).strip().strip('"')
    # A drive letter is a local path, not a URI scheme.
    parsed = urlparse(text) if not (len(text) > 1 and text[1] == ':') else None
    if parsed and parsed.scheme:
        if parsed.scheme.lower() != 'file':
            raise ValueError('use a local input file; remote plugin-input URLs are not accepted')
        if parsed.netloc not in ('', 'localhost'):
            if os.name != 'nt':
                raise ValueError('mount the remote input locally before selecting it')
            text = '//' + parsed.netloc + url2pathname(parsed.path)
        else:
            text = url2pathname(parsed.path)
    path = Path(os.path.expandvars(text)).expanduser().resolve()
    if not path.is_file():
        raise ValueError('input file does not exist or is not a regular file')
    # Validate access without modifying or reading the entire file.
    with path.open('rb'):
        pass
    return str(path)


def validate_options(plugin, supplied, check_files=True):
    """Return (argv, all problems). Does not run a plugin or touch the image."""
    values = effective_values(plugin, supplied)
    args, problems = [], []
    for spec in plugin.get('options', []):
        name, flag, kind = spec['name'], spec['flag'], spec['kind']
        value = values[name]
        if kind == 'bool':
            try:
                enabled = _bool(value)
                values[name] = enabled
                # The CLI uses store_true and may mark the flag required.
                if enabled:
                    args.append(flag)
                elif spec.get('required'):
                    problems.append(flag + ' is required by the engine CLI')
                elif spec.get('default') is True and name in supplied and not _bool(supplied[name]):
                    problems.append(flag + ': this engine option defaults to true and exposes no false flag')
            except ValueError as exc:
                problems.append(flag + ': ' + str(exc))
            continue
        if _empty(value):
            if spec.get('required'):
                problems.append(flag + ' is required' + ('; choose ' + ' / '.join(spec.get('choices', [])) if kind == 'choice' else ''))
            continue
        try:
            if kind == 'int':
                value = str(_integer(value))
            elif kind == 'choice':
                if value not in spec.get('choices', []):
                    raise ValueError('choose ' + ' / '.join(spec.get('choices', [])))
            elif kind == 'list':
                if isinstance(value, str):
                    text = value.strip()
                    value = json.loads(text) if text.startswith('[') else [v.strip() for v in text.split(',') if v.strip()]
                if not isinstance(value, list) or any(isinstance(v, (list, dict)) for v in value):
                    raise ValueError('use a JSON array or comma-separated list')
                minimum = spec.get('min_elements')
                minimum = (1 if spec.get('required') else 0) if minimum is None else minimum
                maximum = spec.get('max_elements')
                if len(value) < minimum:
                    raise ValueError(f'needs at least {minimum} value(s)')
                if maximum and len(value) >= maximum:
                    raise ValueError(f'the engine requires fewer than {maximum} value(s)')
                values[name] = value
                if not value:
                    if spec.get('required'):
                        raise ValueError('needs at least one value for this required CLI flag')
                    continue
                if spec.get('element_type') == 'int':
                    value = [str(_integer(v)) for v in value]
                if any(_empty(v) for v in value):
                    raise ValueError('list values cannot be empty')
                args.extend([flag, *map(str, value)])
                continue
            elif kind not in ('str', 'float'):
                raise ValueError('unsupported option type: ' + kind)
            elif kind == 'float':
                value = str(float(value))
            if spec.get('is_file') and check_files:
                value = _local_file(value)
            args.extend([flag, str(value)])
        except (ValueError, TypeError, OSError) as exc:
            problems.append(flag + ': ' + str(exc))
    module = plugin.get('name', '').rsplit('.', 1)[0]
    names = {s['name'] for s in plugin.get('options', [])}
    # Some plugins enforce one-of constraints only at runtime; catch known ones
    # during planning as well. Never invent PIDs, addresses, rules or files.
    if module == 'windows.pedump':
        pid = not _empty(values.get('pid'))
        kernel = bool(values.get('kernel_module'))
        if pid == kernel:
            problems.append('choose exactly one of --pid or --kernel-module for PE extraction')
    if module == 'windows.pe_symbols' and {'symbols', 'addresses'} <= names:
        if _empty(values.get('symbols')) and _empty(values.get('addresses')):
            problems.append('provide --symbols or --addresses to resolve')
    yara = [k for k in ('yara_file', 'yara_string', 'yara_compiled_file') if k in names]
    if 'yarascan' in module and yara and not any(not _empty(values.get(k)) for k in yara):
        problems.append('provide a YARA rule using ' + ' or '.join('--' + k.replace('_', '-') for k in yara))
    if module == 'windows.dumpfiles' and {'pid', 'virtaddr', 'physaddr'} <= names:
        if not any(not _empty(values.get(k)) for k in ('pid', 'virtaddr', 'physaddr')):
            problems.append('select --pid, --virtaddr or --physaddr before extracting files')
    return args, problems


def plugin_arguments(plugin, values):
    args, problems = validate_options(plugin, values)
    if problems:
        raise PluginOptionsError(plugin, problems)
    return args
