@echo off
echo 🛡️ ShieldGuard Installation
echo ================================

setlocal enabledelayedexpansion
set "ROOT=%~dp0"
set "VENV_PY=%ROOT%venv\Scripts\python.exe"

if exist "%VENV_PY%" (
    set "PYTHON=%VENV_PY%"
) else (
    set "PYTHON=python"
)

echo.
echo 📦 Installing Python dependencies...
"%PYTHON%" -m pip install mitmproxy fastapi uvicorn colorama requests --quiet
if %errorlevel% neq 0 (
    echo ❌ Failed to install Python dependencies
    pause
    exit /b 1
)
echo ✅ Python dependencies installed

echo.
echo 📦 Installing Node.js dependencies...
cd front-end
npm install --silent
if %errorlevel% neq 0 (
    echo ❌ Failed to install Node.js dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo ✅ Node.js dependencies installed

echo.
echo 🎉 Installation complete!
echo.
echo 🚀 To start ShieldGuard:
echo    python fastapi-backend\start.py
echo.
echo 📋 After starting, install the mitmproxy CA certificate:
echo    1. Open certmgr.msc
echo    2. Go to Trusted Root Certification Authorities ^> Certificates
echo    3. Import: %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem
echo.
echo 🖥️  Then open the Electron app:
echo    cd front-end && npm start
echo.
pause