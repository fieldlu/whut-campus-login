@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem ============================================================
rem  WHUT campus network keep-alive launcher (watchdog)
rem  Restarts whut_login.py only when it CRASHES.
rem  Normal exit (0) or user stop (130) ends the watchdog,
rem  so a refused second instance will not loop forever.
rem
rem  Interpreter lookup order:
rem    1) python.local.txt   one line: full path to python.exe (git-ignored)
rem    2) "python" on PATH
rem    3) "py -3" launcher
rem  The chosen interpreter MUST have the "requests" package.
rem ============================================================

set "PYEXE="
set "INTERVAL=300"
set "RETRY_WAIT=10"

rem 1) local override, never committed
if exist "%~dp0python.local.txt" set /p PYEXE=<"%~dp0python.local.txt"

rem 2) python on PATH
if not defined PYEXE for /f "delims=" %%I in ('where python 2^>nul') do if not defined PYEXE set "PYEXE=%%I"

rem 3) py launcher
if not defined PYEXE for /f "delims=" %%I in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined PYEXE set "PYEXE=%%I"

if not defined PYEXE (
    echo [ERROR] Python interpreter not found.
    echo         Create python.local.txt next to this file, containing the full
    echo         path to python.exe, or install Python and add it to PATH.
    pause
    exit /b 1
)

rem dependency check: fail fast with a clear hint instead of a crash loop
"%PYEXE%" -c "import requests" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] the "requests" package is missing for:
    echo         %PYEXE%
    echo         Fix with:  "%PYEXE%" -m pip install requests
    pause
    exit /b 1
)

echo Using interpreter: %PYEXE%
title WHUT KeepAlive - watchdog

:loop
echo.
echo [%date% %time%] starting whut_login.py --watch %INTERVAL%
"%PYEXE%" whut_login.py --watch %INTERVAL%
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
