@echo off
REM ═══════════════════════════════════════════════════════════════
REM SH-DATASET — Ejecucion nativa (Windows)
REM Requiere: Python 3.10+, Wireshark (se detecta automaticamente)
REM ═══════════════════════════════════════════════════════════════
echo.
echo  SH-DATASET Orchestrator
echo  =======================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no encontrado. Instalar desde https://python.org
    pause
    exit /b 1
)

REM Install dependencies
echo Verificando dependencias...
pip install -r requirements.txt --quiet 2>nul
if errorlevel 1 (
    echo [WARN] Algunas dependencias no se instalaron.
)

REM Create dirs
if not exist outputs\pcap mkdir outputs\pcap
if not exist outputs\flows mkdir outputs\flows
if not exist outputs\metadata mkdir outputs\metadata
if not exist outputs\logs mkdir outputs\logs
if not exist saves\scenarios mkdir saves\scenarios
if not exist plugins\attacks mkdir plugins\attacks

echo.
echo Iniciando SH-DATASET...
echo.
python App.py
