<#
Installs the PACKAGED fetch agent (fetch-agent.exe). No Python, pip or internet download needed
on this machine. Run in the employee's own session (not as SYSTEM), from the unzipped package
folder that contains the "fetch-agent" folder:

  powershell -ExecutionPolicy Bypass -File .\install_agent_exe.ps1 -CoordinatorUrl "wss://crawl.yourco.com/agent" -AgentToken "agt_XXXXXXXX"

Same scheduled-task behaviour as install_agent.ps1: starts at logon, on unlock, and a 5-minute
watchdog relaunches it if it died; never times out; runs on battery; never a second copy.
#>
param(
    [Parameter(Mandatory = $true)] [string] $CoordinatorUrl,
    [Parameter(Mandatory = $true)] [string] $AgentToken,
    [string] $InstallDir = "$env:LOCALAPPDATA\FetchAgent",
    [int]    $MaxConcurrency = 2,
    [string] $ActiveHours = "",
    [int]    $DailyMbCap = 500,
    [bool]   $AllowOnBattery = $true
)
$ErrorActionPreference = "Stop"
$TaskName = "FetchAgent"
$Source   = Join-Path $PSScriptRoot "fetch-agent"
$User     = "$env:USERDOMAIN\$env:USERNAME"
$Exe      = Join-Path $InstallDir "fetch-agent.exe"
Write-Host "Source : $Source"
if (-not (Test-Path (Join-Path $Source "fetch-agent.exe"))) {
    throw "fetch-agent\fetch-agent.exe not found next to this script. Unzip the whole package first."
}
Write-Host "Installing packaged fetch agent to $InstallDir for $User"

# Stop any running copy (packaged or the older Python-based one) before replacing files
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Get-Process -Name "fetch-agent" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like "*FetchAgent*agent.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2

# Copy the program, keeping an existing agent.json and logs out of the way of the copy
New-Item -ItemType Directory -Force -Path $InstallDir, "$InstallDir\logs" | Out-Null
foreach ($old in @("venv", "agent.py", "requirements-agent.txt", "_internal", "fetch-agent.exe")) {
    Remove-Item -Recurse -Force (Join-Path $InstallDir $old) -ErrorAction SilentlyContinue
}
Copy-Item -Recurse -Force "$Source\*" $InstallDir

# Config next to the exe, readable only by this user (it holds the agent token)
$cfgPath = Join-Path $InstallDir "agent.json"
@{
    coordinator_url  = $CoordinatorUrl
    agent_token      = $AgentToken
    max_concurrency  = $MaxConcurrency
    active_hours     = $ActiveHours
    daily_mb_cap     = $DailyMbCap
    allow_on_battery = $AllowOnBattery
} | ConvertTo-Json | Set-Content -Path $cfgPath -Encoding UTF8
icacls $cfgPath /inheritance:r /grant:r "${User}:(R,W)" "SYSTEM:(F)" | Out-Null

# ---- Scheduled task
$action   = New-ScheduledTaskAction -Execute $Exe -WorkingDirectory $InstallDir
$atLogon  = New-ScheduledTaskTrigger -AtLogOn -User $User
$stateCls = Get-CimClass -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName "MSFT_TaskSessionStateChangeTrigger"
$onUnlock = New-CimInstance -CimClass $stateCls -ClientOnly -Property @{ StateChange = 8; UserId = $User; Enabled = $true }
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew -Hidden
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($atLogon, $onUnlock, $watchdog) `
    -Settings $settings -Principal $principal -Description "Fetch agent (packaged)" -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 6
$running = Get-Process -Name "fetch-agent" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Agent is running (PID $($running.Id)). Log: $InstallDir\logs\agent.log"
} else {
    Write-Warning "Agent did not stay running. Check $InstallDir\logs\agent.log"
}
Write-Host "To pause: create $env:USERPROFILE\.fetch-agent-pause   To resume: delete it."
