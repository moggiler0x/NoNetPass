@echo off
rem NoNetPass for Windows: double-click to install or update.
rem Asks for administrator rights, then runs install.ps1 (downloads it from GitHub if it is not next to this file).
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)
set "PS1=%~dp0install.ps1"
if not exist "%PS1%" (
  set "PS1=%TEMP%\nonetpass-install.ps1"
  powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/moggiler0x/NoNetPass/ClientPulse/deploy/windows/install.ps1 -OutFile $env:TEMP\nonetpass-install.ps1"
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
pause
