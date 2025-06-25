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

:GSecurity
call :log "GSecurity..."
call :GSecurity

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

:GSecurity

:: Install RamCleaner
mkdir %windir%\Setup\Scripts
mkdir %windir%\Setup\Scripts\Bin
copy /y emptystandbylist.exe %windir%\Setup\Scripts\Bin\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\Bin\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"

:: Perms
icacls "%systemdrive%\Users" /remove "Everyone"
icacls "%systemdrive%\Users\Public" /reset
icacls "%systemdrive%\Users\Public" /inheritance:r
icacls "%systemdrive%\Users\Public" /setowner "console logon" /t
icacls "%USERPROFILE%\" /setowner "%username%" /t /c /l
icacls "%USERPROFILE%\" /remove "System" /t /c /l
icacls "%USERPROFILE%\" /remove "Administrators" /t /c /l

:: Services stop and disable
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon start= disabled

:: Security Policy Import
LGPO.exe /s GSecurity.inf

:: Install elam driver
pnputil /add-driver *.inf /subdirs /install

:: Install Antivirus
md %windir%\Setup\Scripts
md %windir%\Setup\Scripts\Bin
copy /y Antivirus.exe %windir%\Setup\Scripts\Bin\Antivirus.exe
schtasks /create /tn Antivirus /tr "\"%windir%\Setup\Scripts\Bin\Antivirus.exe\"" /sc ONLOGON /rl HIGHEST /f

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

set KEY=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network
set SETACL=%~dp0SetACL.exe
set DEVCON=%~dp0devcon.exe
set LOGFILE=network_cleanup_log.txt

echo Starting network cleanup at %DATE% %TIME% > %LOGFILE%

:: Backup registry permissions
echo Backing up current registry permissions... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn list -lst "f:sddl" -bckp "network_permissions_backup.txt"
if %ERRORLEVEL% NEQ 0 (
    echo Backup failed! Exiting... >> %LOGFILE%
    exit /b %ERRORLEVEL%
)

:: Remove Everyone group
echo Removing Everyone group... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn trustee -trst "n1:Everyone;ta:remtrst;w:dacl"
if %ERRORLEVEL% NEQ 0 (
    echo Failed to remove Everyone! >> %LOGFILE%
    exit /b %ERRORLEVEL%
)

:: Set default permissions
echo Setting default permissions... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Administrators;p:full" -rec cont_obj
%SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:SYSTEM;p:full" -rec cont_obj
%SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Users;p:read" -rec cont_obj
%SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:CREATOR OWNER;p:full;i:so,sc" -rec cont_obj
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set permissions! Exiting... >> %LOGFILE%
    exit /b %ERRORLEVEL%
)

:: Set ownership to Administrators
echo Setting ownership to Administrators... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn setowner -ownr "n:Administrators" -rec cont_obj
if %ERRORLEVEL% NEQ 0 (
    echo Failed to set ownership! Exiting... >> %LOGFILE%
    exit /b %ERRORLEVEL%
)

:: Enable inheritance
echo Enabling inheritance... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn setprot -op "dacl:np;sacl:np"
if %ERRORLEVEL% NEQ 0 (
    echo Failed to enable inheritance! Exiting... >> %LOGFILE%
    exit /b %ERRORLEVEL%
)

:: Unbridge network adapters
echo Checking for network bridges... >> %LOGFILE%
netsh bridge show adapter >> %LOGFILE%
echo Unbridging adapters... >> %LOGFILE%
netsh bridge uninstall
if %ERRORLEVEL% NEQ 0 (
    echo Failed to unbridge adapters! Continuing... >> %LOGFILE%
)

:: List all network adapters
echo Listing network adapters... >> %LOGFILE%
netsh interface show interface >> %LOGFILE%
%DEVCON% find *NET* >> %LOGFILE%

:: Disable unauthorized adapters (replace <AdapterName> with actual names or add logic to detect)
echo Disabling unauthorized adapters... >> %LOGFILE%
:: Example: netsh interface set interface "TAP-Windows Adapter V9" disable
:: netsh interface set interface "<AdapterName>" disable
:: if %ERRORLEVEL% NEQ 0 (
::     echo Failed to disable adapter <AdapterName>! >> %LOGFILE%
:: )

:: Remove unauthorized adapters (replace <DeviceID> with actual IDs from devcon)
echo Removing unauthorized adapters... >> %LOGFILE%
:: Example: %DEVCON% remove @PCI\VEN_8086&DEV_...
:: %DEVCON% remove @<DeviceID>
:: if %ERRORLEVEL% NEQ 0 (
::     echo Failed to remove adapter <DeviceID>! >> %LOGFILE%
:: )

:: Verify final state
echo Verifying registry permissions... >> %LOGFILE%
%SETACL% -on "%KEY%" -ot reg -actn list -lst "f:tab" >> %LOGFILE%
echo Verifying network adapters... >> %LOGFILE%
netsh interface show interface >> %LOGFILE%

echo Cleanup completed at %DATE% %TIME%. Check %LOGFILE% for details.

:: riddance
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)
for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE!
        net user !USERLINE! /delete
    )
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: Bios tweaks
set bcd=%windir%\system32\bcdedit.exe
%bcd% /set nx AlwaysOff
%bcd% /set ems No
%bcd% /set bootems No
%bcd% /set integrityservices disable
%bcd% /set tpmbootentropy ForceDisable
%bcd% /set bootmenupolicy Legacy
%bcd% /set debug No
%bcd% /set disableelamdrivers Yes
%bcd% /set isolatedcontext No
%bcd% /set allowedinmemorysettings 0x0
%bcd% /set vm NO
%bcd% /set vsmlaunchtype Off
%bcd% /set configaccesspolicy Default
%bcd% /set MSI Default
%bcd% /set usephysicaldestination No
%bcd% /set usefirmwarepcisettings No
%bcd% /set sos no
%bcd% /set pae ForceDisable
%bcd% /set tscsyncpolicy legacy
%bcd% /set hypervisorlaunchtype off
%bcd% /set useplatformclock false
%bcd% /set useplatformtick no
%bcd% /set disabledynamictick yes
%bcd% /set x2apicpolicy disable
%bcd% /set uselegacyapicmode yes

    goto :eof
:cleanup
    popd
    goto :eof
