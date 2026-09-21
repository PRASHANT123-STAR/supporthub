@echo off
echo ============================================
echo   SupportHub - Starting Server on Port 8000
echo   URL: http://localhost:8000
echo ============================================
cd /d "%~dp0"
if exist ".\.venv\Scripts\python.exe" (
    .\.venv\Scripts\python.exe -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
) else (
    python -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
)
pause
