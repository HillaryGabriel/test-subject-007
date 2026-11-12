# Installation and Usage

## Windows

### 1. Install Python

Install **Python 3.12 64-bit** from:

https://www.python.org/downloads/

Enable:

```text
Add python.exe to PATH
```

Verify:

```powershell
python --version
python -m pip --version
python -m tkinter
```

### 2. Download Test Subject 007

From GitHub:

```text
Code → Download ZIP
```

Extract it to a simple path, for example:

```text
C:\Forensics\test-subject-007
```

### 3. Launch

Open PowerShell inside the project folder:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

Use this when analyzing Windows memory so Volatility can retrieve required Microsoft symbols.

Future launches:

```powershell
.\RUN-WINDOWS.cmd
```

---

# Kali Linux

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk git
```

Verify:

```bash
python3 --version
python3 -m pip --version
python3 -m tkinter
```

### 2. Clone the project

```bash
git clone https://github.com/HillaryGabriel/test-subject-007.git
cd test-subject-007
```

### 3. Launch

For Windows memory analysis:

```bash
bash RUN-LINUX.sh --online-symbols
```

Future launches:

```bash
bash RUN-LINUX.sh
```

Do not run the GUI with `sudo`.

---

# Memory Analysis

### 1. Import the dump

Inside Test Subject 007:

```text
Import Memory
```

Select the memory image and choose the operating system of the captured machine.

For a Windows dump, select:

```text
Windows
```

even when analyzing from Kali Linux.

### 2. Verify evidence

Confirm the image SHA-256 and verification status.

Windows example:

```powershell
Get-FileHash "C:\Forensics\Evidence\memory.dmp" -Algorithm SHA256
```

Linux example:

```bash
sha256sum ~/Forensics/Evidence/memory.dmp
```

### 3. Test Windows symbols

Before a large Windows investigation, run:

```text
windows.info
```

It should complete successfully.

If symbol errors appear, restart using:

Windows:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

Kali:

```bash
bash RUN-LINUX.sh --online-symbols
```

### 4. Choose an investigation

For an unknown incident, start with the broad forensic investigation.

Use targeted investigations when required:

```text
Process Integrity
Network Evidence
Remote Access & RDP
Suspicious Execution
Persistence
Kernel Integrity
```

### 5. Review results

Review:

- Processes and parent-child relationships
- Command lines
- Suspicious paths
- Services and persistence
- Network connections
- Remote administration tools
- Memory-injection candidates
- Registry and file artifacts
- Timelines
- Data-quality warnings

A suspicious artifact is not automatically malicious.

### 6. Hash executables

Open:

```text
Evidence Lab → Processes & Paths
```

Select the relevant process and, where supported:

```text
Collect Selected PE
```

SHA-256 is calculated only from actual recovered or supplied executable bytes.

### 7. RDP investigations

For stronger RDP timelines, import relevant Windows event evidence such as:

```text
Security.evtx

Microsoft-Windows-TerminalServices-
RemoteConnectionManager/Operational

Microsoft-Windows-TerminalServices-
LocalSessionManager/Operational
```

Keep authentication time, process creation time, and network-object creation time separate.

### 8. Export

Export:

```text
PDF
HTML
CSV
```

Store reports outside the GitHub repository.

---

# Troubleshooting

## Python not found

Windows:

```powershell
python --version
```

If unavailable, reinstall Python and enable:

```text
Add python.exe to PATH
```

## Tkinter missing

Windows:

```powershell
python -m tkinter
```

Linux:

```bash
sudo apt install -y python3-tk
```

## Windows symbol error

Restart using:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

or:

```bash
bash RUN-LINUX.sh --online-symbols
```

Then retry:

```text
windows.info
```

## Linux permission issue

Run:

```bash
bash RUN-LINUX.sh
```

or:

```bash
chmod +x RUN-LINUX.sh
```

---

# Updating

If installed with Git:

```bash
git pull
```

Then restart the application.

If installed using ZIP, download the latest ZIP and extract it into a new application folder.

Do not delete your memory evidence, cases, recovered artifacts, or reports.

---

# Important

Never upload the following to GitHub:

```text
Memory dumps
Case folders
Recovered binaries
Credentials
Sensitive EVTX files
Internal investigation reports
```

Use Test Subject 007 as an investigative workbench. Final conclusions should be validated against the original evidence and other available telemetry.
