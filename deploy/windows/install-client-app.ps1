#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)][string]$SourceBinary,
    [Parameter(Mandatory = $true)][string]$SourceProfile,
    [Parameter(Mandatory = $true)][string]$WintunDll,
    [string]$InstallDirectory = "$env:ProgramFiles\LinkForge",
    [string]$DataDirectory = "$env:ProgramData\LinkForge",
    [string]$Listen = "127.0.0.1:9090"
)

$ErrorActionPreference = "Stop"
foreach ($Path in @($SourceBinary, $SourceProfile, $WintunDll)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}

$Signature = Get-AuthenticodeSignature -FilePath $WintunDll
if ($Signature.Status -ne "Valid") {
    throw "wintun.dll must have a valid Authenticode signature from the official Wintun package."
}

New-Item -ItemType Directory -Force -Path $InstallDirectory, $DataDirectory | Out-Null
$Binary = Join-Path $InstallDirectory "linkforge.exe"
$InstalledWintun = Join-Path $InstallDirectory "wintun.dll"
$Profile = Join-Path $DataDirectory "profile.json"
Copy-Item -LiteralPath $SourceBinary -Destination $Binary -Force
Copy-Item -LiteralPath $WintunDll -Destination $InstalledWintun -Force
Copy-Item -LiteralPath $SourceProfile -Destination $Profile -Force

& icacls.exe $Profile /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null

$ProfileObject = Get-Content -LiteralPath $Profile -Raw | ConvertFrom-Json
if ($ProfileObject.psk_env) {
    $Secret = [Environment]::GetEnvironmentVariable($ProfileObject.psk_env, "Machine")
    if (-not $Secret) {
        throw "Set machine environment variable $($ProfileObject.psk_env) before installation."
    }
}

$Arguments = 'app -profile "' + $Profile + '" -listen ' + $Listen + ' -open=false'
$Action = New-ScheduledTaskAction -Execute $Binary -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)
Register-ScheduledTask -TaskName "LinkForge Client" -Description "One-click encrypted multipath client" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "LinkForge Client"

$Shortcut = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "LinkForge.url"
$Port = ($Listen -split ":")[-1]
Set-Content -LiteralPath $Shortcut -Encoding ASCII -Value @(
    "[InternetShortcut]",
    "URL=http://127.0.0.1:$Port/",
    "IconFile=$Binary",
    "IconIndex=0"
)

Write-Host "LinkForge installed. Double-click the LinkForge desktop shortcut,"
Write-Host "then click Aggregate traffic. No interface or route configuration is required."
