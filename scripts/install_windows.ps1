param([string]$Python = "py", [switch]$CoreOnly)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
function Check-Native([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}
if ($Python -eq "py") {
    & py -3 -c "import sys, tkinter; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
    Check-Native "Install Python 3.10+ with Tcl/Tk support, then retry."
    & py -3 -m venv .venv
} else {
    & $Python -c "import sys, tkinter; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
    Check-Native "The selected Python must include tkinter and be version 3.10+."
    & $Python -m venv .venv
}
Check-Native "Could not create the virtual environment."
$VenvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
Check-Native "Could not update pip. Check approved package access."
if ($CoreOnly) { & $VenvPython -m pip install -e . }
else { & $VenvPython -m pip install -e ".[analysis]" }
Check-Native "Installation failed. Review the error. Core-only installation is available with -CoreOnly."
& $VenvPython -m pip check
Check-Native "Dependency checks failed."
& $VenvPython -m test_subject_007 --doctor
Check-Native "Engine diagnostics failed. Review the output before analysis."
New-Item -ItemType Directory -Force -Path ".setup" | Out-Null
& $VenvPython -m pip freeze | Out-File -Encoding utf8 ".setup\installed-packages.txt"
Write-Host "Installation checks completed. Start with START-WINDOWS.cmd."
