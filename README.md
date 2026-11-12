# Test Subject 007

**GUI-based Windows memory forensics workbench powered by Volatility 3.**

Test Subject 007 helps analysts import a memory dump, run guided Volatility 3 investigations, review evidence, hash recovered executables, and export reports.

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

## Windows

Recommended: **Python 3.12 64-bit**

Download Python:

https://www.python.org/downloads/

During installation enable:

```text
Add python.exe to PATH
```

Download this repository:

```text
Code → Download ZIP
```

Extract it, open PowerShell inside the project folder, then run:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

For later launches:

```powershell
.\RUN-WINDOWS.cmd
```

---

## Kali Linux

Install prerequisites:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk git
```

Clone the project:

```bash
git clone https://github.com/HillaryGabriel/test-subject-007.git
cd test-subject-007
```

Launch:

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

# Evidence Handling

Keep forensic evidence outside the repository.

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

Never upload memory dumps, recovered executables, case folders, credentials, or sensitive reports to GitHub.

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
