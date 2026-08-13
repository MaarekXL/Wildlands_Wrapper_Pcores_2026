@echo off
setlocal
title Ghost Recon Wildlands - Deep Logger v4
cd /d "%~dp0"

echo.
echo ==========================================
echo  Ghost Recon Wildlands - Deep Logger v4
echo ==========================================
echo.
echo Ce test lance Wildlands normalement via Steam.
echo Il NE MODIFIE PAS l'affinite CPU.
echo.
echo Sorties:
echo - CSV telemetry
echo - events.log
echo - summary.txt
echo - ETL WPR avec call stacks
echo - PML Procmon si Procmon64.exe est present
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] Python n'est pas disponible dans le PATH.
    echo.
    echo Installe Python 3 64-bit puis ajoute-le au PATH.
    echo.
    pause
    exit /b 1
)

python -c "import psutil" >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] psutil n'est pas installe.
    echo.
    echo Ouvre PowerShell et lance:
    echo.
    echo     python -m pip install psutil
    echo.
    pause
    exit /b 2
)

if not exist "%~dp0wildlands_deep_logger_v4.py" (
    echo [ERREUR] wildlands_deep_logger_v4.py est introuvable.
    echo.
    pause
    exit /b 3
)

python "%~dp0wildlands_deep_logger_v4.py"
set "RC=%ERRORLEVEL%"

echo.
echo Deep Logger v4 termine avec le code %RC%.
echo.
pause
exit /b %RC%
