@echo off
title PortFootprint - TCP Port Scanner & Fingerprinting Console
cd /d "%~dp0"
echo =======================================================
echo  PortFootprint - TCP Port Scanner & Service Console
echo =======================================================
echo.
echo Launching Interactive Security Console...
echo.
python main.py console
if errorlevel 1 (
    echo.
    echo Console exited with an error. Falling back to command prompt...
)
cmd /k
