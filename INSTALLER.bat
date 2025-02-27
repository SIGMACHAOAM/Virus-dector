@echo off

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python manually from https://www.python.org/downloads/
    exit /b
)

:: Check if pip is installed, and install if missing
python -m ensurepip --upgrade >nul 2>&1
if %errorlevel% neq 0 (
    echo Pip is not installed. Please install pip manually.
    exit /b
)

:: Upgrade pip and install required packages
python -m pip install --upgrade pip
python -m pip install requests
python -m pip install chardet

echo Setup complete. Running script...
start /b python "new43.py"
pause
