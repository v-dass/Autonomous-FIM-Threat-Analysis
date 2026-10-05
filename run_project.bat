@echo off
title Autonomous FIM SOC Dashboard Server
echo ======================================================================
echo    STARTING AUTONOMOUS FIM & THREAT ANALYSIS SYSTEM
echo ======================================================================
echo.
echo [1/2] Launching FastAPI Backend & Live SOC Dashboard...
echo Server running at: http://localhost:8000
echo.
start http://localhost:8000
echo [2/2] Live Server Logs below (Press Ctrl+C to stop):
echo.
.\venv\Scripts\python.exe -m uvicorn src.backend.main:app --reload --port 8000
pause
