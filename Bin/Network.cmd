@echo off
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