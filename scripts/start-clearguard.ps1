$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Starting ClearGuard local agent..."
Write-Host "Open http://127.0.0.1:5288/console.html after the server starts."
python server.py
