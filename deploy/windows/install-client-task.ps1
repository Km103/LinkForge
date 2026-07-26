#Requires -RunAsAdministrator
param(
    [string]$Binary = "C:\Program Files\LinkForge\linkforge.exe",
    [Alias("Config")][string]$Profile = "C:\ProgramData\LinkForge\profile.json",
    [string]$Listen = "127.0.0.1:9090"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Binary)) { throw "LinkForge binary not found: $Binary" }
if (-not (Test-Path $Profile)) { throw "LinkForge profile not found: $Profile" }
$Wintun = Join-Path (Split-Path $Binary) "wintun.dll"
if (-not (Test-Path $Wintun)) { throw "Official wintun.dll not found beside the LinkForge binary: $Wintun" }
$ProfileObject = Get-Content -LiteralPath $Profile -Raw | ConvertFrom-Json
if ($ProfileObject.psk_env -and -not [Environment]::GetEnvironmentVariable($ProfileObject.psk_env, "Machine")) {
    throw "Set the protected machine $($ProfileObject.psk_env) environment value first."
}

$action = New-ScheduledTaskAction -Execute $Binary -Argument ('app -profile "' + $Profile + '" -listen ' + $Listen + ' -open=false')
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)

Register-ScheduledTask -TaskName "LinkForge Client" -Description "One-click encrypted multipath client" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName "LinkForge Client"
Write-Host "LinkForge app task installed. Open http://$Listen/ and click Aggregate traffic."
