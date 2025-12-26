@echo off
setlocal

:: Check if a filename was provided
if "%~1"=="" (
    echo Usage: %~nx0 ^<filename^>
    exit /b 1
)

set FILENAME=%~1
set GHIDRA_VERSION=ghidra_12.0_PUBLIC
set GHIDRA_HOME=%USERPROFILE%\%GHIDRA_VERSION%
:: Run install script
call install.bat

:: Activate virtual environment
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo Virtual environment not found! Run install.bat first.
    exit /b 1
)

:: Run the Python script
python BruteForceAddress.py "%FILENAME%"

endlocal
