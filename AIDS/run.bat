@echo off
title AI-IPS Launcher
color 0A
echo.
echo  ============================================
echo   AI-POWERED INTRUSION PREVENTION SYSTEM
echo   Starting all components...
echo  ============================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERROR] This script requires Administrator privileges!
    echo  Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo  [1/3] Starting IDS Engine...
start "AI-IPS Engine" cmd /k "cd /d %~dp0 && python scripts\train_model.py && python scripts\run_ids.py"

echo  [2/3] Waiting for engine to initialize...
timeout /t 5 /nobreak >nul

echo  [3/3] Starting Dashboard...
start "AI-IPS Dashboard" cmd /k "cd /d %~dp0 && streamlit run dashboard\app.py --server.port 8501"

echo.
echo  ============================================
echo   SYSTEM ONLINE
echo   Dashboard: http://localhost:8501
echo   Press any key to exit this launcher...
echo  ============================================
pause >nul
