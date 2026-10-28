@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  WHUT campus network keep-alive launcher (watchdog)
rem  Restarts whut_login.py only when it CRASHES.
rem  Normal exit (0) or user stop (130) ends the watchdog,
rem  so a refused second instance will not loop forever.
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
set "RC=%errorlevel%"

if "%RC%"=="0" (
    echo [%date% %time%] exited normally ^(code 0^), watchdog stops.
    echo   hint: if it said "already running", close the other window instead.
    goto :done
)
if "%RC%"=="130" (
    echo [%date% %time%] stopped by user ^(Ctrl+C^), watchdog stops.
    goto :done
)

echo [%date% %time%] crashed with code %RC%, restarting in %RETRY_WAIT%s ...
"%SystemRoot%\System32\ping.exe" -n %RETRY_WAIT% 127.0.0.1 >nul
goto loop

:done
echo.
echo Watchdog finished. You can close this window.
pause >nul
endlocal
