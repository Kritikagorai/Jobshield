@echo off
title JobShield Cyber Defense Platform
echo ========================================================
echo Starting JobShield - Fake Job Detector
echo Tagline: Scam hone se pehle pakdo
echo ========================================================
echo.
echo Launching JobShield in default browser...
start http://127.0.0.1:8000/
echo.
echo KEEP THIS WINDOW OPEN while using JobShield!
echo Server running at http://127.0.0.1:8000
echo.
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
