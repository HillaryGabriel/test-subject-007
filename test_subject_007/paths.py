"""User-entered paths and bounded, read-only evidence discovery."""
from __future__ import annotations
import os
from pathlib import Path
from urllib.parse import unquote, urlparse
from .util import fingerprint

DUMP_SUFFIXES = {'.raw', '.mem', '.dmp', '.dump', '.vmem', '.lime', '.bin', '.elf', '.img', '.aff4'}


def user_path(value: str | Path) -> Path:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        text = text[1:-1]
    if not text or '\x00' in text:
        raise ValueError('Paste a file or folder path, or use Browse.')
    if text.lower().startswith('file:'):
        url = urlparse(text)
        text = unquote(url.path)
        if url.netloc and url.netloc != 'localhost':
            text = '//' + url.netloc + text
        if os.name == 'nt' and len(text) > 2 and text[0] == '/' and text[2] == ':':
            text = text[1:]
    return Path(os.path.expandvars(text)).expanduser().resolve()


def workspace_root() -> Path:
    return Path.home() / 'Documents' / 'Test Subject 007'


def inspect_image(path: Path) -> dict:
    path = user_path(path)
    info = fingerprint(path)
    with path.open('rb') as stream:
        magic = stream.read(16)
    if magic.startswith(b'MDMP'):
        raise ValueError('This file is a Windows minidump (MDMP), not a full/kernel memory capture. '
                         'The guided kernel-analysis workflow cannot use this file. Preserve it, '
                         'and select a supported system-memory capture; renaming the file will not convert it.')
    if magic.startswith((b'PK\x03\x04', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!')):
        raise ValueError('This looks like an archive/compressed container, not a directly readable memory image. '
                         'Preserve the original and supply an extracted or acquisition-tool-converted working copy.')
    return {'path': str(path), 'size': info['size'], 'signature_hex': magic.hex(),
            'note': 'Readable file; capture support is checked by Volatility, not by filename.'}


def common_locations() -> list[Path]:
    home = Path.home()
    candidates = [home / name for name in ('Downloads', 'Desktop', 'Documents')]
    candidates += [Path('/media') / home.name, Path('/run/media') / home.name, Path('/mnt')]
    if os.name == 'nt':
        candidates = [home / name for name in ('Downloads', 'Desktop', 'Documents')]
    return [path for path in candidates if path.is_dir()]


def find_dumps(roots: list[Path], cancel=None, max_depth=4, max_entries=40000, max_results=300) -> tuple[list[dict], bool]:
    """Bounded name-only scan. Never reads dump contents or follows directory symlinks."""
    found, seen, visited, limited = [], set(), 0, False
    for root in roots:
        root = user_path(root)
        stack = [(root, 0)]
        while stack:
            if (cancel and cancel.is_set()) or visited >= max_entries or len(found) >= max_results:
                return found, True
            folder, depth = stack.pop()
            try:
                with os.scandir(folder) as entries:
                    for item in entries:
                        visited += 1
                        if visited >= max_entries or len(found) >= max_results:
                            return found, True
                        if item.name.startswith('.') or item.is_symlink():
                            continue
                        if item.is_dir(follow_symlinks=False) and depth < max_depth:
                            stack.append((Path(item.path), depth + 1))
                        elif item.is_file(follow_symlinks=False) and Path(item.name).suffix.lower() in DUMP_SUFFIXES:
                            key = str(Path(item.path).resolve())
                            if key not in seen:
                                stat = item.stat(follow_symlinks=False)
                                found.append({'path': key, 'size': stat.st_size, 'modified': stat.st_mtime})
                                seen.add(key)
            except (PermissionError, OSError):
                continue
    found.sort(key=lambda item: item['modified'], reverse=True)
    return found, limited
