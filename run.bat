@echo off
REM ═══════════════════════════════════════════════════════════════
REM SH-DATASET — Ejecucion nativa (Windows)
REM Requiere: Python 3.10+, Wireshark (dumpcap)
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
    echo [WARN] Algunas dependencias no se instalaron. Continuando...
)

REM Check Wireshark
where dumpcap >nul 2>&1
if errorlevel 1 (
    echo [WARN] Wireshark no encontrado en PATH.
    echo        Captura PCAP requiere Wireshark: https://wireshark.org
    echo        Instalar y agregar a PATH, o el software usara tshark/tcpdump.
    echo.
)

echo Iniciando SH-DATASET...
echo.
python App.py
