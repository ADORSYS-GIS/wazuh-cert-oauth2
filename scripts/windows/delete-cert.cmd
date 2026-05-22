$script = @'
@echo off
setlocal enabledelayedexpansion

set CERT="C:\Program Files (x86)\ossec-agent\etc\sslagent.cert"
set KEY="C:\Program Files (x86)\ossec-agent\etc\sslagent.key"
set AR_LOG="C:\Program Files (x86)\ossec-agent\logs\active-responses.log"
set TAG=delete-cert

call :log INFO "=== delete-cert active response started as %USERNAME% ==="

set DELETED=0

:: Check if files exist and try to delete
for %%F in (%CERT% %KEY%) do (
    if exist %%F (
        call :log INFO "Found: %%F - attempting delete..."
        
        del /f %%F >nul 2>&1
        if !errorlevel! equ 0 (
            call :log INFO "Successfully deleted %%F"
            set /a DELETED+=1
        ) else (
            call :log ERROR "Failed to delete %%F (errorlevel=!errorlevel!)"
            
            :: Try to show who owns/locks it
            echo %DATE% %TIME% %TAG%: [DEBUG] File info for %%F: >> %AR_LOG%
            icacls %%F >> %AR_LOG% 2>&1
            tasklist /fi "imagename eq ossec-agent.exe" >> %AR_LOG% 2>&1
        )
    ) else (
        call :log WARN "File not found: %%F"
    )
)

call :log INFO "=== Finished. Deleted %DELETED% file(s) ==="
exit /b 0

:log
set LEVEL=%~1
set MSG=%~2
for /f "tokens=1-2 delims=T" %%a in ("%DATE%T%TIME%") do set TS=%%a %%b
echo %TS% %TAG%: [%LEVEL%] %MSG% >> %AR_LOG%
exit /b 0
'@