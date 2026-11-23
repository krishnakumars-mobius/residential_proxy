# Removes the fetch agent (packaged exe or Python-based): task, process, install folder.
param([string] $InstallDir = "$env:LOCALAPPDATA\FetchAgent")
$TaskName = "FetchAgent"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Get-Process -Name "fetch-agent" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like "*$InstallDir*agent.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
Remove-Item -Force "$env:USERPROFILE\.fetch-agent-pause" -ErrorAction SilentlyContinue
Write-Host "Fetch agent removed."
