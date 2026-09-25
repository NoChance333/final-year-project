@echo off
title IPFS Kubo Daemon
echo ================================================================
echo  Starting IPFS Daemon (API: 5001, Gateway: 8080)
echo ================================================================

taskkill /F /IM ipfs.exe >nul 2>&1
ping 127.0.0.1 -n 2 >nul

if not exist "%USERPROFILE%\.ipfs" (
    echo Initializing IPFS repository...
    .\ipfs.exe init
)

echo Starting IPFS daemon...
.\ipfs.exe daemon
