@echo off
setlocal

set "DBG_NAME=x%~1dbg.exe" 
set "x64DBG_PATH=C:\Users\Diogo\Desktop\Projetos\Tools\x64Dbg"

:: Check if x64Dbg is already running, and if not start it
tasklist /FI "IMAGENAME eq %DBG_NAME%" | find /I "%DBG_NAME%" >nul

if %ERRORLEVEL% NEQ 0 (
    echo %DBG_NAME% is not running. Starting now...
    start "" "%x64DBG_PATH%\release\x%~1\%DBG_NAME%"                                                 
) else (
    echo %DBG_NAME% is already running.
)

:: Check if PluginDevServer is already running, and if not start it
tasklist /FI "IMAGENAME eq PluginDevServer.exe" | find /I "PluginDevServer.exe" >nul

if %ERRORLEVEL% NEQ 0 (
    echo PluginDevServer.exe is not running. Starting now...
    start "" .\PluginDevServer.exe
) else (
    echo PluginDevServer.exe is already running.
)

:: Check if PluginDevHelper exists in the plugins folder, and if not copy it
if not exist "%x64DBG_PATH%\release\x%~1\plugins\PluginDevHelper.dp%~1" (
    echo Copying x64Sync.dp%~1 to the plugins folder...
    copy "%CD%\PluginDevHelper.dp%~1" "%x64DBG_PATH%\release\x%~1\plugins\PluginDevHelper.dp%~1"
)

:: Check if x64Sync simbolic link exists in the plugins folder, and if not create it
if not exist "%x64DBG_PATH%\release\x%~1\plugins\x64Sync.dp%~1" (
    :: Check if running with admin privileges
    NET SESSION >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo Requesting administrator privileges...
        powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"%CD%\" && %~s0 %*' -Verb RunAs"
        exit
    )

    :: Create symbolic link
    mklink "%x64DBG_PATH%\release\x%~1\plugins\x64Sync.dp%~1" "%CD%\build\%~1-bit\Debug\x64Sync.dp%~1"
)
endlocal
