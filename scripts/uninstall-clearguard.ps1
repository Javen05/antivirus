$ErrorActionPreference = "Stop"

$taskName = "ClearGuard AV Agent"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  Write-Host "ClearGuard startup task removed."
} else {
  Write-Host "ClearGuard startup task was not installed."
}
