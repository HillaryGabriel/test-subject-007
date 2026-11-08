"""Run test modules in isolated processes; CI can reject any skipped check.

Tk interpreter state does not survive between modules. Each GUI module still
exercises real widgets; the process boundary prevents test-only root leakage.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-all', action='store_true', help='Fail on any skipped test (for CI).')
    parser.add_argument('--module', help=argparse.SUPPRESS)
    parser.add_argument('--result-file', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    modules = sorted('tests.' + p.stem for p in (root / 'tests').glob('test_*.py'))
    if args.module:
        if args.module not in modules or not args.result_file:
            parser.error('Invalid isolated test module or missing result file.')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromName(args.module))
        summary = {'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                   'skipped': len(result.skipped), 'successful': result.wasSuccessful()}
        Path(args.result_file).write_text(json.dumps(summary), encoding='utf-8')
        return 0 if result.wasSuccessful() else 1
    total = dict(tests=0, failures=0, errors=0, skipped=0)
    okay = True
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='ts007-tests-') as folder:
        for index, module in enumerate(modules):
            print('\n=== ' + module + ' ===', flush=True)
            result_path = Path(folder) / f'{index}.json'
            try:
                process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--module', module,
                                          '--result-file', str(result_path)], cwd=root, timeout=180)
                if not result_path.is_file():
                    raise RuntimeError('Test module exited without a result summary.')
                detail = json.loads(result_path.read_text(encoding='utf-8'))
                for key in total:
                    total[key] += detail[key]
                okay = okay and process.returncode == 0 and detail['successful']
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                okay = False
                total['errors'] += 1
                print('Module execution error: ' + str(exc), file=sys.stderr)
    passed = total['tests'] - total['failures'] - total['errors'] - total['skipped']
    print(f"\nTOTAL: {total['tests']} tests; {passed} passed; {total['skipped']} skipped; "
          f"{total['failures']} failures; {total['errors']} errors. {time.monotonic()-start:.1f}s", flush=True)
    if args.require_all and total['skipped']:
        print('FAIL: CI requires real-engine and GUI checks; skipped tests are not acceptance.', file=sys.stderr)
        okay = False
    return 0 if okay else 1


if __name__ == '__main__':
    raise SystemExit(main())
