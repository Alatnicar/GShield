@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: =============================================
:: Script Metadata
:: =============================================
set "SCRIPT_NAME=System Cleanup Utility"
set "SCRIPT_VERSION=1.1.0"
set "SCRIPT_UPDATED=2025-06-13"
set "AUTHOR=vocatus (consolidated by Grok/xAI)"

:: =============================================
:: Configuration Variables
:: =============================================
set "LOGPATH=%SystemDrive%\Logs"
set "LOGFILE=%COMPUTERNAME%_system_cleanup.log"
set "FORCE_CLOSE_PROCESSES=yes"
set "FORCE_CLOSE_PROCESSES_EXIT_CODE=1618"
set "LOG_MAX_SIZE=2097152"  :: 2MB
set "NETWORK_KEY=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network"

:: Process and GUID Lists
set "BROWSER_PROCESSES=battle chrome firefox flash iexplore iexplorer opera palemoon plugin-container skype steam yahoo"
set "VNC_PROCESSES=winvnc winvnc4 uvnc_service tvnserver"
set "FLASH_GUIDS_ACTIVE_X=cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c"
set "FLASH_GUIDS_PLUGIN=F6E23569-A22A-4924-93A4-3F215BEF63D2"

:: External Tools
set "SETACL=%~dp0SetACL.exe"
set "DEVCON=%~dp0devcon.exe"
set "LGPO=%~dp0LGPO.exe"

:: =============================================
:: Initialization
:: =============================================
title %SCRIPT_NAME% v%SCRIPT_VERSION% (%SCRIPT_UPDATED%)
call :initialize_environment
if not "%ERRORLEVEL%" == "0" exit /b %ERRORLEVEL%

:: =============================================
:: Main Execution
:: =============================================
call :log "Starting comprehensive system cleanup..."

:: Permission Cleanup
call :clean_permissions

:: Service Management
call :manage_services

:: Network Cleanup
call :clean_network

:: Flash Cleanup
call :cleanup_flash

:: VNC Cleanup
call :cleanup_vnc

:: Temp File Cleanup
call :cleanup_temp

:: USB Cleanup
call :cleanup_usb

:: RAM Cleaner Installation
call :install_ramcleaner

:: User Account Cleanup
call :cleanup_users

:: Final System Settings
call :set_system_policies

:: Completion
call :log "System cleanup complete."
goto :EOF

:: =============================================
:: Core Functions
:: =============================================
:initialize_environment
    call :get_current_date
    if not exist "%LOGPATH%" mkdir "%LOGPATH%" 2>NUL
    pushd "%~dp0"
    call :check_admin_rights
    if not "%ERRORLEVEL%" == "0" exit /b %ERRORLEVEL%
    call :detect_os_version
    call :handle_log_rotation
    goto :EOF

:get_current_date
    for /f "tokens=1 delims=." %%a in ('wmic os get localdatetime ^| find "."') do set "DTS=%%a"
    set "CUR_DATE=!DTS:~0,4!-!DTS:~4,2!-!DTS:~6,2!"
    goto :EOF

:log
    echo %CUR_DATE% %TIME%   %~1 >> "%LOGPATH%\%LOGFILE%"
    echo %CUR_DATE% %TIME%   %~1
    goto :EOF

:check_admin_rights
    net session >nul 2>&1 || (
        call :log "ERROR: Administrative privileges required."
        exit /b 1
    )
    goto :EOF

:detect_os_version
    set "OS_VERSION=OTHER"
    ver | find /i "XP" >NUL && set "OS_VERSION=XP"
    for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| find "ProductName"') do set "WIN_VER=%%i %%j"
    goto :EOF

:handle_log_rotation
    if not exist "%LOGPATH%\%LOGFILE%" echo. > "%LOGPATH%\%LOGFILE%"
    for %%R in ("%LOGPATH%\%LOGFILE%") do if %%~zR GEQ %LOG_MAX_SIZE% (
        pushd "%LOGPATH%"
        del "%LOGFILE%.ancient" 2>NUL
        for %%s in (oldest older old) do if exist "%LOGFILE%.%%s" ren "%LOGFILE%.%%s" "%LOGFILE%.%%s.old" 2>NUL
        ren "%LOGFILE%" "%LOGFILE%.old" 2>NUL
        popd
    )
    goto :EOF

:: =============================================
:: Permission Management
:: =============================================
:clean_permissions
    call :log "Adjusting system permissions..."
    
:: Perms
icacls "%systemdrive%\Users" /remove "Everyone"
icacls "%systemdrive%\Users\Public" /reset
icacls "%systemdrive%\Users\Public" /inheritance:r
icacls "%systemdrive%\Users\Public" /setowner "console logon" /t
icacls "%USERPROFILE%\" /setowner "%username%" /t /c /l
icacls "%USERPROFILE%\" /remove "System" /t /c /l
icacls "%USERPROFILE%\" /remove "Administrators" /t /c /l

:: Mini filter drivers
fltmc unload bfs
fltmc unload unionfs
takeown /f %windir%\system32\drivers\bfs.sys /A
takeown /f %windir%\system32\drivers\unionfs.sys /A
icacls %windir%\system32\drivers\bfs.sys /reset
icacls %windir%\system32\drivers\unionfs.sys /reset
icacls %windir%\system32\drivers\bfs.sys /inheritance:d
icacls %windir%\system32\drivers\unionfs.sys /inheritance:d
del %windir%\system32\drivers\bfs.sys /y
del %windir%\system32\drivers\unionfs.sys /y

:: Security Policy Import
LGPO.exe /s GSecurity.inf

:: Install elam driver
pnputil /add-driver *.inf /subdirs /install

:: Install Antivirus
md %windir%\Setup\Scripts
md %windir%\Setup\Scripts\Bin
copy /y Antivirus.exe %windir%\Setup\Scripts\Bin\Antivirus.exe
schtasks /create /tn Antivirus /tr "\"%windir%\Setup\Scripts\Bin\Antivirus.exe\"" /sc ONLOGON /rl HIGHEST /f
    
    goto :EOF

:: =============================================
:: Service Management
:: =============================================
:manage_services
    call :log "Managing system services..."
    
    :: Stop and disable services
    sc stop LanmanWorkstation
    sc stop LanmanServer
    sc stop seclogon
    sc config LanmanWorkstation start= disabled
    sc config LanmanServer start= disabled
    sc config seclogon start= disabled
    
    :: Import security policy
    if exist "%LGPO%" (
        %LGPO% /s GSecurity.inf
    ) else (
        call :log "WARNING: LGPO.exe not found, skipping security policy import"
    )
    
    goto :EOF

:: =============================================
:: Network Cleanup
:: =============================================
:clean_network
    call :log "Cleaning network configuration..."
    
    :: Backup registry permissions
    if exist "%SETACL%" (
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn list -lst "f:sddl" -bckp "network_permissions_backup.txt"
        if %ERRORLEVEL% NEQ 0 (
            call :log "WARNING: Failed to backup network registry permissions"
        )
        
        :: Remove Everyone group
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn trustee -trst "n1:Everyone;ta:remtrst;w:dacl"
        
        :: Set default permissions
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn ace -ace "n:Administrators;p:full" -rec cont_obj
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn ace -ace "n:SYSTEM;p:full" -rec cont_obj
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn ace -ace "n:Users;p:read" -rec cont_obj
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn ace -ace "n:CREATOR OWNER;p:full;i:so,sc" -rec cont_obj
        
        :: Set ownership to Administrators
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn setowner -ownr "n:Administrators" -rec cont_obj
        
        :: Enable inheritance
        %SETACL% -on "%NETWORK_KEY%" -ot reg -actn setprot -op "dacl:np;sacl:np"
    else
        call :log "WARNING: SetACL.exe not found, skipping network registry cleanup"
    )
    
    :: Network bridge cleanup
    call :log "Checking for network bridges..."
    netsh bridge show adapter >> "%LOGPATH%\%LOGFILE%"
    call :log "Unbridging adapters..."
    netsh bridge uninstall
    
    :: Network adapter management
    call :log "Listing network adapters..."
    netsh interface show interface >> "%LOGPATH%\%LOGFILE%"
    if exist "%DEVCON%" (
        %DEVCON% find *NET* >> "%LOGPATH%\%LOGFILE%"
    )
    
    goto :EOF

:: =============================================
:: Flash Cleanup
:: =============================================
:cleanup_flash
    call :log "Cleaning Adobe Flash Player..."
    
    if /i "%FORCE_CLOSE_PROCESSES%"=="yes" (
        call :force_close_flash
    ) else (
        call :check_flash_processes
    )
    
    call :remove_flash
    goto :EOF

:force_close_flash
    call :log "Closing Flash-related processes..."
    for %%i in (%BROWSER_PROCESSES%) do taskkill /F /IM "%%i*" /T >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :EOF

:check_flash_processes
    call :log "Checking for running Flash processes..."
    for %%i in (%BROWSER_PROCESSES%) do (
        for /f "delims=" %%a in ('tasklist ^| find /i "%%i"') do (
            if not "%%a"=="" (
                call :log "ERROR: Process '%%i' running, aborting Flash cleanup."
                exit /b %FORCE_CLOSE_PROCESSES_EXIT_CODE%
            )
        )
    )
    goto :EOF

:remove_flash
    call :log "Removing Flash Player..."
    wmic product where "name like 'Adobe Flash Player%%'" uninstall /nointeractive >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%g in (%FLASH_GUIDS_ACTIVE_X% %FLASH_GUIDS_PLUGIN%) do (
        MsiExec.exe /uninstall {%%g} /quiet /norestart >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    goto :EOF

:: =============================================
:: VNC Cleanup
:: =============================================
:cleanup_vnc
    call :log "Cleaning VNC installations..."
    
    call :log "Stopping VNC services..."
    for %%s in (%VNC_PROCESSES%) do (
        net stop %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
        taskkill /F /IM %%s.exe >> "%LOGPATH%\%LOGFILE%" 2>NUL
        sc delete %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    
    call :log "Removing VNC registry entries..."
    for %%k in (UltraVNC ORL RealVNC TightVNC) do (
        reg delete "HKLM\SOFTWARE\%%k" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    
    call :log "Removing VNC files..."
    for %%d in (UltraVNC "uvnc bvba" RealVNC TightVNC) do (
        rd /s /q "%ProgramFiles%\%%d" 2>NUL
        rd /s /q "%ProgramFiles(x86)%\%%d" 2>NUL
    )
    
    goto :EOF

:: =============================================
:: Temp File Cleanup
:: =============================================
:cleanup_temp
    call :log "Cleaning temporary files..."
    
    del /F /S /Q "%TEMP%\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    
    if /i "%WIN_VER:~0,9%"=="Microsoft" (
        for /D %%x in ("%SystemDrive%\Documents and Settings\*") do call :clean_user_xp "%%x"
    ) else (
        for /D %%x in ("%SystemDrive%\Users\*") do call :clean_user_vista "%%x"
    )
    
    call :log "Cleaning system temp files..."
    del /F /S /Q "%WINDIR%\TEMP\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%i in (NVIDIA ATI AMD Dell Intel HP) do (
        rmdir /S /Q "%SystemDrive%\%%i" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    
    goto :EOF

:clean_user_xp
    del /F /Q "%~1\Local Settings\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /Q "%~1\Recent\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :EOF

:clean_user_vista
    del /F /S /Q "%~1\AppData\Local\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /S /Q "%~1\AppData\Roaming\Macromedia\Flash Player\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :EOF

:: =============================================
:: USB Cleanup
:: =============================================
:cleanup_usb
    call :log "Cleaning USB device registry..."
    
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    
    goto :EOF

:: =============================================
:: RAM Cleaner Installation
:: =============================================
:install_ramcleaner
    call :log "Installing RamCleaner..."
    
    mkdir %windir%\Setup\Scripts\Bin 2>NUL
    if exist "emptystandbylist.exe" (
        copy /y emptystandbylist.exe %windir%\Setup\Scripts\Bin\emptystandbylist.exe
    )
    if exist "RamCleaner.bat" (
        copy /y RamCleaner.bat %windir%\Setup\Scripts\Bin\RamCleaner.bat
    )
    if exist "RamCleaner.xml" (
        schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"
    )
    
    goto :EOF

:: =============================================
:: User Account Cleanup
:: =============================================
:cleanup_users
    call :log "Cleaning up user accounts..."
    
    for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
        set "USERNAME=%%z"
        set "USERSID=%%y"
    )
    
    for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
    
    for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
        set "USERLINE=%%u"
        set "USERRID=!USERLINE:~-4!"
        if !USERRID! neq !RID! (
            call :log "Removing user: !USERLINE!"
            net user !USERLINE! /delete
        )
    )
    
    goto :EOF

:: =============================================
:: System Policy Settings
:: =============================================
:set_system_policies
    call :log "Applying system policies..."
    
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    
    goto :EOF

:: =============================================
:: Script Termination
:: =============================================
:EOF
    popd
    exit /b 0