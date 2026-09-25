@echo off
title Geth v1.17.6 - Local Ethereum Node
echo ================================================================
echo  Starting Geth v1.17.6 Node in final-year-project\blockchain
echo  RPC: http://127.0.0.1:8545 ^| Network ID: 12345
echo ================================================================

taskkill /F /IM geth.exe >nul 2>&1
ping 127.0.0.1 -n 2 >nul

if not exist data\geth (
    echo Initializing datadir with genesis.json...
    .\geth.exe --datadir .\data init .\genesis.json
)

echo Launching Geth...
.\geth.exe --datadir .\data --dev --dev.period 0 --password .\data\password.txt --networkid 12345 --http --http.addr 0.0.0.0 --http.port 8545 --http.corsdomain "*" --http.vhosts "*" --http.api "eth,net,web3,admin" --ipcdisable

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Geth exited with error code %ERRORLEVEL%.
    pause
)
