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