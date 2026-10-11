# Windows 서비스 등록 (관리자 PowerShell에서 실행). 설치 폴더는 인자로 지정.
#   .\install-windows-service.ps1 -InstallDir "C:\Program Files\NetworkScanner\service"
param([string]$InstallDir = "C:\Program Files\NetworkScanner\service")
$exe = Join-Path $InstallDir "netscan-service.exe"
if (-not (Test-Path $exe)) { throw "not found: $exe" }
sc.exe create NetworkScanner binPath= "`"$exe`"" start= delayed-auto DisplayName= "NetworkScanner Scheduler"
sc.exe description NetworkScanner "Runs scheduled network scans, uploads results and sends alerts."
sc.exe failure NetworkScanner reset= 86400 actions= restart/10000/restart/60000/restart/300000
Start-Service NetworkScanner
Write-Host "Installed. Settings: %APPDATA%\NetworkScanner\settings.json of the service account."
