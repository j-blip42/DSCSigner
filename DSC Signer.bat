@echo off
rem Starts the DSC Signer web interface from the source in this folder.
rem The first run installs any missing libraries; after that it just starts.
cd /d "%~dp0"

rem Find Python: on the PATH if it is there, otherwise in the folders the
rem python.org installer uses, newest version first.
set "PY="
for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | find /i "WindowsApps" >nul || if not defined PY set "PY=%%P"
)
if not defined PY (
    for /f "delims=" %%D in ('dir /b /ad /o-n "%LOCALAPPDATA%\Programs\Python\Python3*" 2^>nul') do (
        if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
    )
)
if not defined PY (
    for /f "delims=" %%D in ('dir /b /ad /o-n "%ProgramFiles%\Python3*" 2^>nul') do (
        if not defined PY if exist "%ProgramFiles%\%%D\python.exe" set "PY=%ProgramFiles%\%%D\python.exe"
    )
)
if not defined PY (
    echo Python was not found. Install it from python.org and tick
    echo "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)
echo Using %PY%

"%PY%" -c "import pyhanko, fitz, pkcs11, PIL, win32com" >nul 2>nul
if errorlevel 1 (
    echo Installing the libraries the signer needs - first run only...
    "%PY%" -m pip install pyhanko pymupdf python-pkcs11 pillow pywin32
    if errorlevel 1 (
        echo.
        echo The install failed - see the messages above.
        pause
        exit /b 1
    )
)

"%PY%" sign_dsc_ui.py
if errorlevel 1 pause
