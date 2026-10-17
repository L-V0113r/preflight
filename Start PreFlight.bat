@echo off
rem  Double-click to start PreFlight. Leave this window open while browsing.
title PreFlight scanner
call "%~dp0backend\setup_windows.bat" || goto :failed
cd /d "%~dp0backend"
".venv\Scripts\python.exe" run_server.py
pause
exit /b

:failed
echo.
echo  PreFlight could not be set up. See the message above.
pause
