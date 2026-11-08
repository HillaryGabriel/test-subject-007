#!/usr/bin/env bash
# One command for first setup and subsequent launches. No evidence is deleted.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$ROOT"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  printf '%s\n' 'Run the desktop application as your normal analyst account, not with sudo.' >&2
  exit 1
fi
NO_INSTALL=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --no-install) NO_INSTALL=1 ;;
    *) ARGS+=("$arg") ;;
  esac
done
if [[ ! -x .venv/bin/python ]] || ! .venv/bin/python -c 'import test_subject_007, tkinter, volatility3, reportlab, defusedxml' >/dev/null 2>&1; then
  if [[ "$NO_INSTALL" -eq 1 ]]; then
    printf '%s\n' 'The environment is not installed. Run: bash INSTALL-LINUX.sh' >&2
    exit 1
  fi
  bash INSTALL-LINUX.sh
fi
if [[ -z "${DISPLAY:-}" ]]; then
  printf '%s\n' 'A graphical desktop/X display is required. Start this from your Linux desktop terminal.' >&2
  exit 1
fi
exec .venv/bin/python -m test_subject_007 "${ARGS[@]}"
