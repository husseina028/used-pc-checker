@echo off
setlocal
title Used PC Checker USB

set "ROOT=%~dp0"
set "SCRIPT=%ROOT%PC_Checker\scripts\Run-UsedPcCheck.ps1"
set "SCREEN_TEST=%ROOT%PC_Checker\tools\Screen_Keyboard_Test.html"
set "KEYBOARD_TEST=%ROOT%PC_Checker\tools\Keyboard_Checker.html"
set "PORT_CHECKER=%ROOT%PC_Checker\scripts\Port_Checker.ps1"
set "CHECKLIST=%ROOT%PC_Checker\checklists\Used_Laptop_Buyer_Checklist.txt"

if not exist "%SCRIPT%" (
    echo Missing checker script:
    echo %SCRIPT%
    echo.
    pause
    exit /b 1
)
if not exist "%KEYBOARD_TEST%" (
    echo Missing keyboard checker:
    echo %KEYBOARD_TEST%
    echo.
    pause
    exit /b 1
)
if not exist "%PORT_CHECKER%" (
    echo Missing port checker:
    echo %PORT_CHECKER%
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ==================================================
echo              USED PC CHECKER USB
echo ==================================================
echo.
echo  1. Full automated check  ^(recommended, asks for admin, includes CrystalDiskInfo^)
echo  2. Quick automated check ^(no admin, fewer checks, includes CrystalDiskInfo^)
echo  3. Keyboard checker ^(choose 100%% or 60%% layout^)
echo  4. Port checker ^(USB, charger, HDMI, audio, network^)
echo  5. CrystalDiskInfo drive health report
echo  6. Screen / touchpad / camera / speaker test
echo  7. Open used laptop buying checklist
echo  8. Open saved reports folder
echo  9. Exit
echo.
choice /c 123456789 /n /m "Choose an option [1-9]: "
set "PICK=%ERRORLEVEL%"

if "%PICK%"=="255" exit /b 1
if "%PICK%"=="0" exit /b 1

if "%PICK%"=="9" exit /b 0

if "%PICK%"=="8" (
    if not exist "%ROOT%Reports" mkdir "%ROOT%Reports"
    start "" "%ROOT%Reports"
    goto menu
)

if "%PICK%"=="7" (
    start "" "%CHECKLIST%"
    goto menu
)

if "%PICK%"=="6" (
    start "" "%SCREEN_TEST%"
    goto menu
)

if "%PICK%"=="5" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -CrystalDiskInfoOnly -LaunchCrystalDiskInfo
    goto menu
)

if "%PICK%"=="4" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PORT_CHECKER%"
    goto menu
)

if "%PICK%"=="3" (
    start "" "%KEYBOARD_TEST%"
    goto menu
)

if "%PICK%"=="2" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -NoAdmin
    goto menu
)

if "%PICK%"=="1" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -TryElevate
    goto menu
)

goto menu
