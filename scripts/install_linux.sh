#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
PYTHON="${PYTHON:-python3}"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  printf '%s\n' 'Do not run the application installer with sudo. Install OS prerequisites separately.' >&2
  exit 1
fi
"$PYTHON" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10 or newer is required"'
if ! "$PYTHON" -c 'import tkinter, venv' >/dev/null 2>&1; then
  printf '%s\n' 'Install OS prerequisites first: sudo apt install python3 python3-venv python3-pip python3-tk' >&2
  exit 1
fi
mkdir -p .setup
exec > >(tee -a .setup/install.log) 2>&1
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --upgrade pip
if [[ "${1:-}" == '--core-only' ]]; then
  .venv/bin/python -m pip install -e .
else
  .venv/bin/python -m pip install -e '.[analysis]'
fi
.venv/bin/python -m pip check
.venv/bin/python -m test_subject_007 --doctor
.venv/bin/python -m pip freeze > .setup/installed-packages.txt
printf '\n%s\n' 'Setup completed. Run: bash RUN-LINUX.sh' 'Setup log: .setup/install.log'
