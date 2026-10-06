@echo off
rem NEON//PING launcher (Windows CMD)
rem   start.bat            starts the GUI without a console window (pythonw)
rem   start.bat --console  starts with a visible console (python), useful for debugging
setlocal
cd /d "%~dp0"

if not exist "%~dp0neonping.py" (
    echo [NEON//PING] neonping.py was not found next to this .bat file.
    pause
    exit /b 1
)

if /i "%~1"=="--console" goto console

where pythonw >nul 2>nul && ( start "" pythonw "%~dp0neonping.py" & exit /b 0 )
where pyw     >nul 2>nul && ( start "" pyw -3 "%~dp0neonping.py" & exit /b 0 )
where python  >nul 2>nul && ( start "" python "%~dp0neonping.py" & exit /b 0 )
goto nopython

:console
where python >nul 2>nul && ( python "%~dp0neonping.py" & pause & exit /b 0 )
where py     >nul 2>nul && ( py -3 "%~dp0neonping.py" & pause & exit /b 0 )

:nopython
echo [NEON//PING] Python was not found in PATH.
echo              Install Python 3 (python.org) or add python.exe to PATH.
pause
exit /b 1
