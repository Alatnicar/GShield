@echo off

:: Perms
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%systemdrive%\Users\Public /A
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
