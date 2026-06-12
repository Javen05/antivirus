$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$server = Join-Path $root "server.py"
$pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source

if (-not (Test-Path -LiteralPath $server)) {
  throw "server.py was not found. Run this script from the ClearGuard scripts folder."
}

if (-not $pythonw) {
  if (-not $python) {
    throw "Python was not found. Install Python 3.11+ and try again."
  }
  $pythonw = $python
}

$taskName = "ClearGuard Agent"
$action = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$server`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Starts the ClearGuard local antivirus agent when the user signs in." -Force | Out-Null

Start-ScheduledTask -TaskName $taskName

Write-Host "ClearGuard persistence installed."
Write-Host "It will start when you sign in after reboot."
Write-Host "Open http://127.0.0.1:5288/console.html"
Write-Host "Run PowerShell as Administrator before launching ClearGuard if you want firewall block/unblock actions."
