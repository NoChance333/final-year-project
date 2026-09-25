@echo off
title Stop Geth Node
echo Stopping Geth node...
taskkill /F /IM geth.exe >nul 2>&1
echo Geth node stopped successfully.
timeout /t 2 >nul
