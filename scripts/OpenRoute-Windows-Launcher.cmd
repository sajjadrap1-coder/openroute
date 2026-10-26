@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "BASEDIR=%~dp0"
if not exist "%BASEDIR%OpenRoute-Tunnel-Windows-x64-v0.2.0-alpha.exe" set "BASEDIR=%~dp0..\"
cd /d "%BASEDIR%"
set "APP=%BASEDIR%OpenRoute-Tunnel-Windows-x64-v0.2.0-alpha.exe"
if not exist "%APP%" (
  echo OpenRoute executable not found next to this launcher.
  echo Download the Windows alpha package and keep its directory structure.
  pause
  exit /b 1
)
:menu
cls
echo ===========================================
echo   OpenRoute Tunnel v0.2.0-alpha
 echo   Private TLS 1.3 TCP relay - NOT a VPN
 echo ===========================================
echo 1. Generate one-time mutual TLS identities
 echo 2. Start local HTTP CONNECT proxy
 echo 3. Start LOCAL TEST relay only
 echo 4. Exit
 echo.
set /p "MODE=Select option [1-4]: "
if "%MODE%"=="1" goto init
if "%MODE%"=="2" goto proxy
if "%MODE%"=="3" goto relay
if "%MODE%"=="4" exit /b 0
goto menu
:init
"%APP%" init --dir identities
pause
goto menu
:proxy
if not exist "identities\client.crt" (
  echo Missing identities\client.crt; contact the consenting relay operator.
  pause
  goto menu
)
set /p "HOST=Enter trusted volunteer relay host:port [example: 198.51.100.10:9443]: "
if "%HOST%"=="" goto menu
"%APP%" proxy --listen 127.0.0.1:8787 --relay "%HOST%" --identities identities
pause
goto menu
:relay
if not exist "identities\relay.crt" (
 echo Missing identities\relay.crt; generate certificates first.
 pause
 goto menu
)
set /p "ALLOW=Exact approved domain:port [example.org:443]: "
if "%ALLOW%"=="" goto menu
"%APP%" relay --listen 127.0.0.1:9443 --allow "%ALLOW%" --identities identities
pause
goto menu
