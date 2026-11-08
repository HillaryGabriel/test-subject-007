@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" goto setup
".venv\Scripts\python.exe" -c "import test_subject_007, tkinter, volatility3, reportlab, defusedxml" >nul 2>&1
if errorlevel 1 goto setup
goto launch
:setup
call INSTALL-WINDOWS.cmd
if errorlevel 1 exit /b 1
:launch
".venv\Scripts\python.exe" -m test_subject_007 %*
if errorlevel 1 (
  echo Startup failed. Review the message above.
  pause
  exit /b 1
)
