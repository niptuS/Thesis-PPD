@echo off
REM ═══════════════════════════════════════════════════════════════
REM SH-DATASET — Docker execution (portability/reproducibility)
REM Requires: Docker Desktop
REM ═══════════════════════════════════════════════════════════════
echo.
echo  SH-DATASET Docker
echo  ==================
echo.
echo  NOTE: On Docker Desktop (Windows/Mac) the network interfaces
echo        shown belong to the internal VM, not the physical PC.
echo        For Wi-Fi/Ethernet capture, use: run.bat
echo.

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker not found. Install Docker Desktop.
    pause
    exit /b 1
)

echo Building image...
docker compose build --quiet 2>nul || docker-compose build --quiet 2>nul
if errorlevel 1 (
    echo [ERROR] Build failed. Check Dockerfile and Docker Desktop.
    pause
    exit /b 1
)

echo Starting interactive container...
echo.
docker compose run --rm sh-dataset 2>nul || docker-compose run --rm sh-dataset 2>nul
