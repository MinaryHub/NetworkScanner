# Windows 서비스 제거 (관리자 PowerShell에서 실행). 설치 파일과 설정/데이터 폴더는 남긴다.
#   .\uninstall-windows-service.ps1
#   .\uninstall-windows-service.ps1 -ServiceName KetworkScanner
[CmdletBinding()]
param(
    [string]$ServiceName = "KetworkScanner"
)

$ErrorActionPreference = "Stop"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Service '$ServiceName' is not installed."
    exit 0
}

if ($svc.Status -ne "Stopped") {
    Write-Host "Stopping '$ServiceName'..."
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
}

& sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)" }
Write-Host "Removed service '$ServiceName'. Binaries and the settings/data folder were left in place."
