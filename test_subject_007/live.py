"""Incremental, non-destructive live display of engine files, including CR progress."""
from __future__ import annotations
import codecs
import re
import time
from pathlib import Path

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
PROGRESS = re.compile(r'Progress:\s*([\d.]+)\s*(.*)', re.I)


class FileCursor:
    """Read only newly written bytes. Raw files are never changed for presentation."""
    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

    def read(self, maximum=65536, final=False):
        if not self.path.exists():
            return ''
        if self.path.stat().st_size < self.offset:
            self.offset = 0
            self.decoder.reset()
        with self.path.open('rb') as stream:
            stream.seek(self.offset)
            data = stream.read(maximum)
            self.offset += len(data)
        return self.decoder.decode(data, final=final and self.offset >= self.path.stat().st_size)

    @property
    def pending(self):
        return self.path.exists() and self.offset < self.path.stat().st_size


class LiveFiles:
    """Bound each UI event but keep all original bytes on disk. No blocking pipes."""
    def __init__(self, folder, run_id, plugin, emit):
        self.files = {name: FileCursor(Path(folder) / filename) for name, filename in
                      [('stderr', 'stderr.log'), ('stdout', 'stdout.csv'), ('engine', 'volatility.log')]}
        self.run_id, self.plugin, self.emit = run_id, plugin, emit
        self.last_output = time.monotonic()
        self.progress = None
        self.phase = 'Starting engine'
        self.fragments = {name: '' for name in self.files}

    def poll(self, final=False):
        for source, cursor in self.files.items():
            # One bounded block per heartbeat; after process exit drain remaining output.
            while True:
                # Avoid flooding Tk when a plugin produces output faster than the viewer.
                # Only the live preview is skipped, never the on-disk evidence.
                if cursor.path.exists() and cursor.path.stat().st_size - cursor.offset > 2*1024*1024:
                    skipped = cursor.path.stat().st_size - cursor.offset - 256*1024
                    cursor.offset += skipped
                    cursor.decoder.reset()
                    self.emit('run_log', {'run_id':self.run_id,'plugin':self.plugin,'source':'app',
                        'text':f'Live {source} preview skipped {skipped:,} older bytes to stay responsive. Complete output is preserved in {cursor.path.name}.\n'})
                text = cursor.read(final=final)
                if text:
                    self.last_output = time.monotonic()
                    text = ANSI.sub('', text).replace('\r\n', '\n').replace('\r', '\n')
                    if source == 'stderr':
                        search = self.fragments[source] + text
                        for match in PROGRESS.finditer(search):
                            try:
                                self.progress = min(100.0, max(0.0, float(match[1])))
                                self.phase = match[2].strip() or 'Engine operation'
                            except ValueError:
                                pass
                        self.fragments[source] = search[-2048:]
                    self.emit('run_log', {'run_id': self.run_id, 'plugin': self.plugin,
                                         'source': source, 'text': text})
                if not final or not cursor.pending:
                    break
        return {'percent': self.progress, 'phase': self.phase,
                'quiet_seconds': time.monotonic() - self.last_output,
                'bytes_written': sum(c.path.stat().st_size if c.path.exists() else 0 for c in self.files.values())}
