@echo off
setlocal
cd /d "%~dp0"
where.exe pythonw.exe >nul 2>&1
if errorlevel 1 goto missing
start "" pythonw.exe -B -X utf8 "%~dp0app.pyw"
exit /b 0
:missing
echo Python 3.10 or newer with tkinter is required on PATH.
echo Alternative command: python -B app.pyw
pause
exit /b 1
