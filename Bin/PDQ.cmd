@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: Script Metadata
set "SCRIPT_NAME=System Cleanup Utility"
set "SCRIPT_VERSION=1.0.0"
set "SCRIPT_UPDATED=2025-03-10"
set "AUTHOR=vocatus (consolidated by Grok/xAI)"

:: Configuration Variables
set "LOGPATH=%SystemDrive%\Logs"
set "LOGFILE=%COMPUTERNAME%_system_cleanup.log"
set "FORCE_CLOSE_PROCESSES=yes"
set "FORCE_CLOSE_PROCESSES_EXIT_CODE=1618"
set "LOG_MAX_SIZE=2097152"  :: 2MB

:: Process and GUID Lists
set "BROWSER_PROCESSES=battle chrome firefox flash iexplore iexplorer opera palemoon plugin-container skype steam yahoo"
set "VNC_PROCESSES=winvnc winvnc4 uvnc_service tvnserver"
set "FLASH_GUIDS_ACTIVE_X=cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c ..."
set "FLASH_GUIDS_PLUGIN=F6E23569-A22A-4924-93A4-3F215BEF63D2 ..."

:: Initialize Environment
title %SCRIPT_NAME% v%SCRIPT_VERSION% (%SCRIPT_UPDATED%)
call :get_current_date
if not exist "%LOGPATH%" mkdir "%LOGPATH%" 2>NUL
pushd "%~dp0"
call :check_admin_rights
call :detect_os_version
call :handle_log_rotation

:: Main Execution
call :log "Starting system cleanup..."

:cleanup_flash
call :log "Cleaning Adobe Flash Player..."
if /i "%FORCE_CLOSE_PROCESSES%"=="yes" (call :force_close_flash) else (call :check_flash_processes)
call :remove_flash

:cleanup_vnc
call :log "Cleaning VNC installations..."
call :remove_vnc

:cleanup_temp
call :log "Cleaning temporary files..."
call :clean_temp_files

:cleanup_usb
call :log "Cleaning USB device registry..."
call :clean_usb_devices

:complete
call :log "System cleanup complete."
:: No exit here, script will continue
goto :cleanup

:: Core Functions
:get_current_date
    for /f "tokens=1 delims=." %%a in ('wmic os get localdatetime ^| find "."') do set "DTS=%%a"
    set "CUR_DATE=!DTS:~0,4!-!DTS:~4,2!-!DTS:~6,2!"
    :: Return control to the caller
    goto :eof

:log
    echo %CUR_DATE% %TIME%   %~1 >> "%LOGPATH%\%LOGFILE%"
    echo %CUR_DATE% %TIME%   %~1
    :: Return control to the caller
    goto :eof

:check_admin_rights
    net session >nul 2>&1 || (
        call :log "ERROR: Administrative privileges required."
        :: No exit here, returning control
        goto :eof
    )
    goto :eof

:detect_os_version
    set "OS_VERSION=OTHER"
    ver | find /i "XP" >NUL && set "OS_VERSION=XP"
    for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| find "ProductName"') do set "WIN_VER=%%i %%j"
    goto :eof

:handle_log_rotation
    if not exist "%LOGPATH%\%LOGFILE%" echo. > "%LOGPATH%\%LOGFILE%"
    for %%R in ("%LOGPATH%\%LOGFILE%") do if %%~zR GEQ %LOG_MAX_SIZE% (
        pushd "%LOGPATH%"
        del "%LOGFILE%.ancient" 2>NUL
        for %%s in (oldest older old) do if exist "%LOGFILE%.%%s" ren "%LOGFILE%.%%s" "%LOGFILE%.%%s.old" 2>NUL
        ren "%LOGFILE%" "%LOGFILE%.old" 2>NUL
        popd
    )
    goto :eof

:: Flash Cleanup Functions
:force_close_flash
    call :log "Closing Flash-related processes..."
    for %%i in (%BROWSER_PROCESSES%) do taskkill /F /IM "%%i*" /T >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:check_flash_processes
    call :log "Checking for running Flash processes..."
    for %%i in (%BROWSER_PROCESSES%) do (
        for /f "delims=" %%a in ('tasklist ^| find /i "%%i"') do (
            if not "%%a"=="" (
                call :log "ERROR: Process '%%i' running, aborting."
                goto :eof
            )
        )
    )
    goto :eof

:remove_flash
    call :log "Removing Flash Player..."
    wmic product where "name like 'Adobe Flash Player%%'" uninstall /nointeractive >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%g in (%FLASH_GUIDS_ACTIVE_X% %FLASH_GUIDS_PLUGIN%) do MsiExec.exe /uninstall {%%g} /quiet /norestart >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: VNC Cleanup Functions
:remove_vnc
    call :log "Stopping VNC services..."
    for %%s in (%VNC_PROCESSES%) do (
        net stop %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
        taskkill /F /IM %%s.exe >> "%LOGPATH%\%LOGFILE%" 2>NUL
        sc delete %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    call :log "Removing VNC registry entries..."
    for %%k in (UltraVNC ORL RealVNC TightVNC) do reg delete "HKLM\SOFTWARE\%%k" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    call :log "Removing VNC files..."
    for %%d in (UltraVNC "uvnc bvba" RealVNC TightVNC) do (
        rd /s /q "%ProgramFiles%\%%d" 2>NUL
        rd /s /q "%ProgramFiles(x86)%\%%d" 2>NUL
    )
    goto :eof

:: Temp File Cleanup Functions
:clean_temp_files
    call :log "Cleaning user temp files..."
    del /F /S /Q "%TEMP%\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    if /i "%WIN_VER:~0,9%"=="Microsoft" (
        for /D %%x in ("%SystemDrive%\Documents and Settings\*") do call :clean_user_xp "%%x"
    ) else (
        for /D %%x in ("%SystemDrive%\Users\*") do call :clean_user_vista "%%x"
    )
    call :log "Cleaning system temp files..."
    del /F /S /Q "%WINDIR%\TEMP\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%i in (NVIDIA ATI AMD Dell Intel HP) do rmdir /S /Q "%SystemDrive%\%%i" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_xp
    del /F /Q "%~1\Local Settings\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /Q "%~1\Recent\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_vista
    del /F /S /Q "%~1\AppData\Local\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /S /Q "%~1\AppData\Roaming\Macromedia\Flash Player\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: USB Device Cleanup (Removed third-party tools)
:clean_usb_devices
    call :log "Cleaning USB device registry..."
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:cleanup
    popd
    goto :eof
