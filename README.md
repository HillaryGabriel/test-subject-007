# Test Subject 007

**GUI-based Windows memory forensics workbench powered by Volatility 3.**

Test Subject 007 helps analysts import memory dumps, run guided Volatility 3 investigations, review forensic evidence, hash recovered executables, and export investigation reports.

## Main Features

- Process and process-tree analysis
- Command-line and suspicious execution review
- Network and remote-access investigation
- Persistence analysis
- Memory-injection review
- Services, files, DLLs and registry evidence
- Process and network timelines
- Executable SHA-256 hashing
- EVTX/XML timeline import
- PDF, HTML and CSV reporting
- Windows and Kali Linux support

> Findings are investigative leads. They are not automatic proof of malware or compromise.

---

# Quick Install

## Python Version

Recommended:

```text
Python 3.12 64-bit
```

Tested:

```text
Python 3.11–3.12
```

Avoid for now:

```text
Python 3.13+
```

Some dependencies such as `yara-python` may fail to install correctly on newer Python versions.

---

## Windows

### 1. Install Python 3.12

Download Python:

https://www.python.org/downloads/

During installation enable:

```text
Add python.exe to PATH
```

Check installed Python versions:

```powershell
py -0p
```

Verify Python 3.12:

```powershell
py -3.12 --version
```

Expected:

```text
Python 3.12.x
```

---

### 2. Download Test Subject 007

From this GitHub repository select:

```text
Code → Download ZIP
```

Extract the ZIP.

Open PowerShell inside the extracted project folder.

---

### 3. Check the Python Used by Test Subject 007

If `.venv` already exists, check its Python version:

```powershell
.\.venv\Scripts\python.exe --version
```

If it shows Python 3.13 or newer, delete the old virtual environment:

```powershell
Remove-Item -Recurse -Force .venv
```

Create a new environment using Python 3.12:

```powershell
py -3.12 -m venv .venv
```

Verify:

```powershell
.\.venv\Scripts\python.exe --version
```

Expected:

```text
Python 3.12.x
```

> Installing Python 3.12 does not automatically change an existing `.venv`. Delete and recreate `.venv` if it was created using a newer Python version.

---

### 4. Launch

For Windows memory analysis:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

For later launches:

```powershell
.\RUN-WINDOWS.cmd
```

---

## Kali Linux

### 1. Install Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk git
```

Check Python:

```bash
python3 --version
```

Python 3.12 is recommended.

If available:

```bash
python3.12 --version
```

---

### 2. Clone Test Subject 007

```bash
git clone https://github.com/HillaryGabriel/test-subject-007.git
cd test-subject-007
```

---

### 3. Create a Python 3.12 Environment

If `.venv` already exists and was created using a newer Python version:

```bash
rm -rf .venv
```

Create the environment:

```bash
python3.12 -m venv .venv
```

Verify:

```bash
./.venv/bin/python --version
```

Expected:

```text
Python 3.12.x
```

---

### 4. Launch

```bash
bash RUN-LINUX.sh --online-symbols
```

For later launches:

```bash
bash RUN-LINUX.sh
```

Do not run the application with `sudo`.

---

# Basic Investigation Workflow

```text
Import Memory
→ Select captured OS
→ Verify evidence hash
→ Run windows.info
→ Choose investigation
→ Start analysis
→ Review findings
→ Use Evidence Lab if needed
→ Export report
```

For an unknown Windows incident, start with the broad forensic investigation, then review:

- Process Integrity
- Network Evidence
- Remote Access & RDP
- Suspicious Execution
- Persistence
- Kernel Integrity

---

# Optional EVTX Import

Windows event logs are **not automatically imported from the memory dump**.

For stronger authentication or RDP timelines, manually import relevant EVTX/XML evidence through the Evidence Lab.

Examples:

```text
Security.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager
Microsoft-Windows-TerminalServices-LocalSessionManager
```

Memory timestamps and event-log timestamps should be interpreted separately.

---

# Evidence Handling

Keep forensic evidence outside the GitHub repository.

Example Windows structure:

```text
C:\Forensics\
├── Evidence\
├── Recovered\
└── Reports\
```

Example Linux structure:

```text
~/Forensics/
├── Evidence/
├── Recovered/
└── Reports/
```

Never upload memory dumps, recovered executables, case folders, credentials, EVTX evidence, or sensitive investigation reports to GitHub.

---

# Documentation

- [Installation and Usage](docs/INSTALL-AND-USE.md)
- [Investigation Scope](docs/INVESTIGATIONS.md)
- [DFIR Evidence Interpretation](docs/DFIR-UPDATE.md)
- [Validation](docs/VALIDATION.md)

---

# Repository

https://github.com/HillaryGabriel/test-subject-007

Test Subject 007 is an independent project and is not an official Volatility Foundation product.
