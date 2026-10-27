@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  WHUT campus network keep-alive launcher (watchdog)
rem  Restarts whut_login.py automatically whenever it exits.
rem  Edit PYTHON below if your interpreter path differs.
rem ============================================================

set "PYTHON=C:\Python313\python.exe"
set "INTERVAL=300"
set "RETRY_WAIT=10"

if not exist "%PYTHON%" (
    echo [ERROR] Python not found: %PYTHON%
    echo         Edit the PYTHON variable at the top of this file.
    pause
    exit /b 1
)

title WHUT KeepAlive - watchdog

:loop
echo.
echo [%date% %time%] starting whut_login.py --watch %INTERVAL%
"%PYTHON%" whut_login.py --watch %INTERVAL%
echo [%date% %time%] exited with code %errorlevel%, restarting in %RETRY_WAIT%s ...
"%SystemRoot%\System32\ping.exe" -n %RETRY_WAIT% 127.0.0.1 >nul
goto loop
