@echo off
echo Installing Git Submodules...
git submodule update --init --recursive

echo Need to install 'virtualenv', and 'OpenJDK 21' to run Tool

:: Check and install virtualenv (assumes Python is already installed)
where virtualenv >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing virtualenv...
    pip install virtualenv
) else (
    echo virtualenv already installed
)

:: Check and install OpenJDK 21
where java >nul 2>&1
if %errorlevel% neq 0 (
    echo Please Install OpenJDK 21 from https://adoptium.net/temurin/releases/?os=windows&package=jdk&version=21
    exit /b 1
) else (
    echo Java is already installed
)

:: Set path variables
set GHIDRA_VERSION=ghidra_11.3.2_PUBLIC
set GHIDRA_ZIP=%USERPROFILE%\%GHIDRA_VERSION%_20250415.zip
set GHIDRA_HOME=%USERPROFILE%\%GHIDRA_VERSION%

if not exist "%GHIDRA_HOME%" (
    echo Downloading Ghidra 11.3.2...
    powershell -Command "Invoke-WebRequest -Uri https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/%GHIDRA_VERSION%_20250415.zip -OutFile '%GHIDRA_ZIP%'"
    powershell -Command "Expand-Archive -Path '%GHIDRA_ZIP%' -DestinationPath '%USERPROFILE%'"
    del "%GHIDRA_ZIP%"
    echo Ghidra 11.3.2 downloaded and extracted to %GHIDRA_HOME%
) else (
    echo Ghidra 11.3.2 already installed in %GHIDRA_HOME%
)

:: Set GHIDRA_HOME if not already set
if defined GHIDRA_HOME (
    echo Ghidra home already set to %GHIDRA_HOME%
) else (
    echo Setting GHIDRA_HOME...
    setx GHIDRA_HOME "%GHIDRA_HOME%"
    echo GHIDRA_HOME set to %GHIDRA_HOME% (you may need to restart your terminal)
)

:: Create ghidra_scripts folder if not exists
if not exist "%USERPROFILE%\ghidra_scripts" (
    echo Creating ghidra_scripts directory...
    mkdir "%USERPROFILE%\ghidra_scripts"
) else (
    echo ghidra_scripts directory already exists
)

echo Copying scripts to ghidra_scripts...
xcopy /Y /E ghidra_scripts "%USERPROFILE%\ghidra_scripts"

:: Create and activate virtual environment
if not exist ".venv" (
    echo Creating virtual environment...
    virtualenv .venv
) else (
    echo Virtual environment already exists
)

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing requirements...
pip install -r requirements.txt

echo You will need to run ".venv\Scripts\activate.bat" to activate the virtual environment before running the scripts.
echo All done!
exit /b 0
