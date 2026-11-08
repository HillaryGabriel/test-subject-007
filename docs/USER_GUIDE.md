# Install and use the evidence-led Test Subject 007 update

## Preserve evidence first

Close the old application. Keep original captures, cases (case.json, runs, audit.jsonl), reports, extracted artifacts and locally supplied symbols. Do not delete the repository or evidence to install this update. This source archive contains no old virtual environment and needs no files from a deleted application.

## Kali / Ubuntu / Debian desktop

Use a separate application directory. For the supplied full ZIP saved in Downloads:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk unzip
mkdir -p "$HOME/Tools/ts007-dfir"
unzip "$HOME/Downloads/Test-Subject-007-DFIR-Update.zip" -d "$HOME/Tools/ts007-dfir"
cd "$HOME/Tools/ts007-dfir/test-subject-007"
bash RUN-LINUX.sh
```

For approved Windows-symbol downloads, use `bash RUN-LINUX.sh --online-symbols`. For future launches run `bash RUN-LINUX.sh`. Use the normal desktop account, not sudo. The first launch needs approved package sources. For a private repository download, extract Code > Download ZIP and open a terminal in its folder containing pyproject.toml; the folder may be named test-subject-007-main. The launch command is the same.

To update an existing installation after replacing its source, refresh dependencies:

```bash
.venv/bin/python -m pip install -e '.[analysis]'
.venv/bin/python -m pip check
.venv/bin/python -m test_subject_007 --doctor
bash RUN-LINUX.sh
```

The new XML dependency is defusedxml; EVTX support is provided by python-evtx in the analysis extra. The launcher's import check detects missing mandatory XML support. Optional EVTX support must still be installed for EVTX imports. Installation errors are not successful analysis; inspect .setup/install.log.

## Windows desktop

Use a supported 64-bit Python installation with Tcl/Tk (the CI matrix targets 3.11/3.12). Extract the complete source into a new directory, such as `C:\Tools\ts007-dfir\test-subject-007`. Double-click RUN-WINDOWS.cmd. For approved symbol downloads, run ` .\RUN-WINDOWS.cmd --online-symbols` in PowerShell in that directory.

For an existing environment after source replacement:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[analysis]"
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m test_subject_007 --doctor
.\RUN-WINDOWS.cmd
```

No virtual-environment activation or machine-wide PowerShell-policy change is required. Never copy .venv from another machine.

## Existing case: improve the report without rerunning the capture

1. Open case and select the folder containing case.json.
2. In Findings, click Rebuild findings. Older cached rule output is not treated as current.
3. Review the actionable list; turn on Include background context to review contextual groups.
4. In Evidence lab, inspect Processes & paths. Double-click for source references and identity limitations.
5. To obtain a reconstructed Windows image hash, select a process and choose Collect selected PE. Confirm the request. Review status under Files & SHA-256. A successful plugin with no recovered binary has no executable hash.
6. For an original acquired file, use Add acquired file. A selected process association is analyst supplied. Never execute the file. Import a locally validated hash-intelligence CSV only when the list's source is known.
7. For event-backed RDP timing, use Timeline & logons > Import EVTX / XML. Select external or memory-recovered provenance accurately. This app does not automatically carve logs from the dump.
8. Record a scoped conclusion under Analyst assessment only with rationale and supporting references. Do not call access authorized from an IP/port alone.
9. Set SAVE REPORTS TO and export a new PDF/HTML/CSV bundle. Copy LAST SAVED PATH or use Open folder. Previous reports and original plugin output remain unchanged.

An existing run may contain Created timestamps that the earlier PDF omitted; rebuilding can expose them. Missing timestamps, files and events cannot be manufactured. Run additional supported plugins or import preserved evidence when needed. Symbols still must match the capture; Linux needs an exact matching kernel ISF.

## Acceptance before operational use

Run GitHub's Windows/Linux test matrix for your updated commit. On an authorized reference capture, compare the same plugin/options/raw output with direct CLI, test live logs/cancellation, recover and hash a known test executable, and compare imported events against the original EVTX/XML. Record known limits. Passing software tests is not certification of real-capture forensic correctness.
