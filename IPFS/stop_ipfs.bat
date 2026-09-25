@echo off
title Stop IPFS Daemon
echo Stopping IPFS daemon...
taskkill /F /IM ipfs.exe >nul 2>&1
echo IPFS daemon stopped successfully.
timeout /t 2 >nul
