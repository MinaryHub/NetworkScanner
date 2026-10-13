# Windows 서비스 등록 (관리자 PowerShell에서 실행). 설치 폴더는 인자로 지정.
#   .\install-windows-service.ps1 -InstallDir "C:\Program Files\KetworkScanner\service"
#   .\install-windows-service.ps1 -Credential (Get-Credential)            # 지정한 사용자 계정으로 실행
#   .\install-windows-service.ps1 -Account "NT AUTHORITY\NetworkService"  # 가상 계정으로 실행
# 서비스는 실행 계정의 %APPDATA%\KetworkScanner\settings.json 을 읽는다(GUI에서 저장한 것과 같은 파일).
# LocalSystem(기본)으로 돌리면 GUI 사용자의 설정이 아니라 시스템 프로필의 설정을 읽으므로, 보통은 GUI를 쓰는
# 사용자 계정(-Credential)으로 등록하는 편이 설정을 공유하기 쉽다.
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\KetworkScanner\service",
    [string]$ServiceName = "KetworkScanner",
    # 서비스를 실행할 사용자 계정(암호 포함). 생략하면 -Account 또는 LocalSystem.
    [System.Management.Automation.PSCredential]$Credential,
    # 암호 없는 가상/관리 계정 이름(예: "NT AUTHORITY\NetworkService", "NT AUTHORITY\LocalService").
    [string]$Account
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "netscan-service.exe"
if (-not (Test-Path $exe)) { throw "not found: $exe" }

$createArgs = @("create", $ServiceName, "binPath=", "`"$exe`"", "start=", "delayed-auto", "DisplayName=", "KetworkScanner Scheduler")
$runAs = "LocalSystem"
if ($Credential) {
    $user = $Credential.UserName
    if ($user -notmatch '\\|@') { $user = ".\$user" }   # 도메인 없는 로컬 계정은 ".\" 접두사가 필요하다
    $createArgs += @("obj=", $user, "password=", $Credential.GetNetworkCredential().Password)
    $runAs = $user
} elseif ($Account) {
    $createArgs += @("obj=", $Account)
    $runAs = $Account
}

& sc.exe @createArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed (exit $LASTEXITCODE). Is the service already installed? Run uninstall-windows-service.ps1 first." }
& sc.exe description $ServiceName "Runs scheduled network scans, uploads results and sends alerts." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/60000/restart/300000 | Out-Null
Start-Service $ServiceName

# 실행 계정이 실제로 읽게 될 settings.json 경로를 계산해 보여 준다.
function Resolve-SettingsPath([string]$runAsAccount) {
    $windir = $env:SystemRoot
    switch -Regex ($runAsAccount) {
        '^LocalSystem$'                         { return "$windir\System32\config\systemprofile\AppData\Roaming\KetworkScanner\settings.json" }
        '^NT AUTHORITY\\NetworkService$'        { return "$windir\ServiceProfiles\NetworkService\AppData\Roaming\KetworkScanner\settings.json" }
        '^NT AUTHORITY\\LocalService$'          { return "$windir\ServiceProfiles\LocalService\AppData\Roaming\KetworkScanner\settings.json" }
        default {
            $name = ($runAsAccount -split '[\\@]')[-1]
            if ($runAsAccount -match '@') { $name = ($runAsAccount -split '@')[0] }
            $profiles = Split-Path $env:USERPROFILE -Parent
            return (Join-Path $profiles "$name\AppData\Roaming\KetworkScanner\settings.json") + "  (profile is created on first logon/run)"
        }
    }
}

Write-Host "Installed service '$ServiceName' running as $runAs."
Write-Host "Settings file used by the service: $(Resolve-SettingsPath $runAs)"
Write-Host "Logs: <same folder>\logs\  -  Uninstall with: .\uninstall-windows-service.ps1 -ServiceName $ServiceName"
