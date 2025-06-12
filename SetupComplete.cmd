@echo off

:: Script Metadata
set "SCRIPT_NAME=GSecurity"
set "SCRIPT_VERSION=3.6.1"
set "SCRIPT_UPDATED=01.06.2025"
set "AUTHOR=Gorstak"
Title GSecurity && Color 0b

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 1: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion

:: Step 2: Move to the script directory
cd /d %~dp0

:: Step 3: Move to the 'Bin' subfolder
cd Bin

:: Step 4: Set PowerShell Execution Policy to Bypass for current user
echo Setting PowerShell Execution Policy to Bypass for current user...
powershell -Command "Set-ExecutionPolicy Bypass -Force"

:: Step 5: Initialize environment 
setlocal EnableExtensions DisableDelayedExpansion

:: Step 6: Execute PowerShell (.ps1) files alphabetically
echo Executing PowerShell scripts...
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    echo Running %%A...
    if /i "%%A"=="GSecurity.ps1" (
        powershell -ExecutionPolicy Bypass -File "%%A" -NoMonitor -NonInteractive
    ) else (
        powershell -ExecutionPolicy Bypass -File "%%A"
    )
    if %ERRORLEVEL% NEQ 0 (
        echo Error: %%A failed with exit code %ERRORLEVEL%
    )
)

:: Step 7: Execute Registry (.reg) files alphabetically
echo Executing Registry files...
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    echo Merging %%C...
    reg import "%%C"
    if %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to merge %%C with exit code %ERRORLEVEL%
    )
)

:: Step 8: Execute CMD (.cmd) files alphabetically
echo Executing CMD scripts...
for /f "tokens=*" %%B in ('dir /b /o:n *.cmd') do (
    echo Running %%B...
    call "%%B"
    if %ERRORLEVEL% NEQ 0 (
        echo Error: %%B failed with exit code %ERRORLEVEL%
    )
)

echo Script completed successfully.
exit
