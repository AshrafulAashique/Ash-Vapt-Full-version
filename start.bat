@echo off
title VAPT Backend
echo Starting VAPT ^& OSINT Scanner backend...
start /B /MIN pythonw vapt_scanner.py 2>nul || start /MIN python vapt_scanner.py
timeout /t 2 /nobreak >nul
start "" "%~dp0index.html"
