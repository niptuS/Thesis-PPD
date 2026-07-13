@echo off
REM ═══════════════════════════════════════════════════════════════
REM SH-DATASET — Native execution (Windows)
REM Requires: Python 3.10+, Wireshark (auto-detected)
REM ═══════════════════════════════════════════════════════════════
echo.
echo  SH-DATASET Orchestrator
echo  =======================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM Install dependencies
echo Checking dependencies...
pip install -r requirements.txt --quiet 2>nul
if errorlevel 1 (
    echo [WARN] Some dependencies were not installed.
)

REM Create dirs
if not exist outputs\pcap mkdir outputs\pcap
if not exist outputs\flows mkdir outputs\flows
if not exist outputs\metadata mkdir outputs\metadata
if not exist outputs\logs mkdir outputs\logs
if not exist saves\scenarios mkdir saves\scenarios
if not exist plugins\attacks mkdir plugins\attacks

echo.
python App.py
