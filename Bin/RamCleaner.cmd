@echo off

REM Install RamCleaner
mkdir %windir%\Setup\Scripts\Bin
copy /y emptystandbylist.exe %windir%\Setup\Scripts\Bin\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\Bin\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"
