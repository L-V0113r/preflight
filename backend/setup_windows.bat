@echo off
rem ------------------------------------------------------------------
rem  PreFlight one-time setup for Windows (called by the Start scripts).
rem  Creates a private Python environment in backend\.venv, installs the
rem  libraries, trains the model on this computer and runs the tests.
rem ------------------------------------------------------------------
cd /d "%~dp0"
if exist ".venv\preflight_ready.txt" exit /b 0

echo.
echo  Setting up PreFlight for the first time. This takes about a minute.
echo.
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv 2>nul || python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
    echo  Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
    echo  and tick "Add python.exe to PATH" during installation, then run this again.
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
    echo  Installing the Python libraries failed. Check your internet connection and try again.
    exit /b 1
)
echo  Training the model on this computer...
".venv\Scripts\python.exe" train_model.py
if errorlevel 1 exit /b 1
echo  Running the self-tests...
".venv\Scripts\python.exe" -m unittest
if errorlevel 1 (
    echo  Some self-tests failed. PreFlight will still start, but please report the errors above.
)
echo ready> ".venv\preflight_ready.txt"
exit /b 0
