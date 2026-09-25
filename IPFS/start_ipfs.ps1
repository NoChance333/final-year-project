# Start IPFS Daemon
$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptDir)) { $ScriptDir = Get-Location }

$ipfsExe = Join-Path $ScriptDir "ipfs.exe"

# Check if IPFS is initialized
$ipfsRepo = Join-Path $env:USERPROFILE ".ipfs"
if (!(Test-Path $ipfsRepo)) {
    Write-Host "Initializing IPFS repository..."
    & $ipfsExe init
}

# Check if already running
$existing = Get-Process ipfs -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "IPFS daemon is already running (PID: $($existing.Id))."
    exit 0
}

Write-Host "Starting IPFS daemon..."
$proc = Start-Process -FilePath $ipfsExe -ArgumentList "daemon" -WindowStyle Hidden -PassThru
Write-Host "Started IPFS daemon (PID: $($proc.Id))"
Write-Host "API: http://127.0.0.1:5001"
Write-Host "Gateway: http://127.0.0.1:8080"
