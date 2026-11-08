@echo off
setlocal
cd /d "%~dp0"
echo Test Subject 007 - install for Windows
py -3 -c "import sys, tkinter; assert sys.maxsize > 2**32 and sys.version_info >= (3, 10), 'Supported 64-bit Python required'"
if errorlevel 1 (
  echo Install a supported 64-bit Python with Tcl/Tk support, then try again.
  echo The manual Python installation commands are in README.md.
  pause
  exit /b 1
)
py -3 -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -e ".[analysis]"
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m test_subject_007 --doctor
if errorlevel 1 goto failed
echo.
echo Installation complete. Open START-WINDOWS.cmd to launch Test Subject 007.
pause
exit /b 0
:failed
echo.
echo Installation did not complete. Review the error above and README.md.
pause
exit /b 1
