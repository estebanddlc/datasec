$ErrorActionPreference = "Stop"

$taskName = "datasec-monitor"
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonCmd = (Get-Command py.exe -ErrorAction SilentlyContinue)

if (-not $pythonCmd) {
    throw "py.exe was not found. Install Python from python.org and try again."
}

$actionArgs = "-m datasec.main monitor run --once"
$action = New-ScheduledTaskAction -Execute $pythonCmd.Source -Argument $actionArgs -WorkingDirectory $repoRoot
$triggerAtLogon = New-ScheduledTaskTrigger -AtLogOn
$triggerRecurring = New-ScheduledTaskTrigger -Once (Get-Date).Date.AddMinutes(5)
$triggerRecurring.Repetition = New-ScheduledTaskRepetitionSettingsSet -Interval (New-TimeSpan -Hours 6) -Duration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger @($triggerAtLogon, $triggerRecurring) `
    -Settings $settings `
    -Description "Run datasec breach monitoring for the current user" `
    -Force | Out-Null

Write-Host "Scheduled task '$taskName' installed."
Write-Host "It will run at logon and then every 6 hours."
