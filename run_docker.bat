@echo off
REM ═══════════════════════════════════════════════════════════════
REM SH-DATASET — Ejecucion Docker (portabilidad/reproducibilidad)
REM Requiere: Docker Desktop
REM ═══════════════════════════════════════════════════════════════
echo.
echo  SH-DATASET Docker
echo  ==================
echo.
echo  NOTA: En Docker Desktop (Windows/Mac) las interfaces de red
echo        mostradas son de la VM interna, no del PC fisico.
echo        Para captura en Wi-Fi/Ethernet, usar: run.bat
echo.

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker no encontrado. Instalar Docker Desktop.
    pause
    exit /b 1
)

echo Construyendo imagen...
docker compose build --quiet 2>nul || docker-compose build --quiet 2>nul
if errorlevel 1 (
    echo [ERROR] Fallo al construir. Verificar Dockerfile y Docker Desktop.
    pause
    exit /b 1
)

echo Iniciando contenedor interactivo...
echo.
docker compose run --rm sh-dataset 2>nul || docker-compose run --rm sh-dataset 2>nul
