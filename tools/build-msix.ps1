<#
.SYNOPSIS
  KetworkScanner GUI 를 MSIX 로 패키징한다(Windows, Windows SDK 의 makeappx/signtool 사용).
.EXAMPLE
  pwsh tools/build-msix.ps1 -Rid win-x64
  pwsh tools/build-msix.ps1 -Rid win-x64,win-arm64 -Bundle -PfxPath .\sideload.pfx -PfxPassword secret
.NOTES
  Identity 값은 Partner Center 의 Product identity 와 같아야 한다. Store 제출본은 서명하지 않는다(-PfxPath 생략).
#>
[CmdletBinding()]
param(
  [string[]]$Rid = @("win-x64"),
  [string]$OutDir = (Join-Path $PSScriptRoot "..\release-packages\msix"),
  [string]$IdentityName = $(if ($env:MSIX_IDENTITY_NAME) { $env:MSIX_IDENTITY_NAME } else { "SMIC.KetworkScanner" }),
  [string]$Publisher = $(if ($env:MSIX_PUBLISHER) { $env:MSIX_PUBLISHER } else { "CN=SMIC" }),
  [string]$PublisherDisplay = $(if ($env:MSIX_PUBLISHER_DISPLAY) { $env:MSIX_PUBLISHER_DISPLAY } else { "minary" }),
  [string]$Version = $env:MSIX_VERSION,
  [switch]$Bundle,
  [string]$PfxPath,
  [string]$PfxPassword
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$proj = Join-Path $root "KetworkScanner.Avalonia\KetworkScanner.Avalonia.csproj"
$csprojVersion = ([xml](Get-Content $proj)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $Version) { $Version = "$csprojVersion.0" }

function Find-SdkTool($name) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  $found = Get-ChildItem -Path $kits -Recurse -Filter $name -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $found) { throw "$name not found - install the Windows 10/11 SDK" }
  return $found.FullName
}
$makeappx = Find-SdkTool "makeappx.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$packages = @()
foreach ($r in $Rid) {
  $arch = switch ($r) { "win-x64" { "x64" } "win-arm64" { "arm64" } default { throw "unsupported RID $r" } }
  $stage = Join-Path ([IO.Path]::GetTempPath()) ("ketwork-msix-" + [Guid]::NewGuid().ToString("N"))
  $app = Join-Path $stage "app"; $pkg = Join-Path $stage "pkg"
  Write-Host "Publishing $r (StoreBuild) ..."
  dotnet publish $proj -c Release -r $r --self-contained -p:StoreBuild=true -p:Version=$csprojVersion -o $app --nologo -v q
  if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
  New-Item -ItemType Directory -Force -Path (Join-Path $pkg "Assets") | Out-Null
  Copy-Item -Path (Join-Path $app "*") -Destination $pkg -Recurse -Force
  Copy-Item -Path (Join-Path $root "KetworkScanner.Avalonia\Package\Assets\*.png") -Destination (Join-Path $pkg "Assets")
  Get-ChildItem $pkg -Filter *.pdb | Remove-Item -Force
  $manifest = Get-Content (Join-Path $root "KetworkScanner.Avalonia\Package\AppxManifest.xml") -Raw
  $manifest = $manifest.Replace("__IDENTITY_NAME__", $IdentityName).Replace("__PUBLISHER__", $Publisher).Replace("__PUBLISHER_DISPLAY__", $PublisherDisplay).Replace("__VERSION__", $Version).Replace("__ARCH__", $arch)
  Set-Content -Path (Join-Path $pkg "AppxManifest.xml") -Value $manifest -Encoding UTF8
  $msix = Join-Path $OutDir "KetworkScanner-$Version-$arch.msix"
  & $makeappx pack /o /d $pkg /p $msix
  if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed" }
  $packages += $msix
  Remove-Item $stage -Recurse -Force
}
if ($Bundle -and $packages.Count -gt 0) {
  $bundleDir = Join-Path ([IO.Path]::GetTempPath()) ("ketwork-bundle-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null
  $packages | ForEach-Object { Copy-Item $_ $bundleDir }
  $bundle = Join-Path $OutDir "KetworkScanner-$Version.msixbundle"
  & $makeappx bundle /o /d $bundleDir /p $bundle
  if ($LASTEXITCODE -ne 0) { throw "makeappx bundle failed" }
  $packages += $bundle
  Remove-Item $bundleDir -Recurse -Force
}
if ($PfxPath) {
  $signtool = Find-SdkTool "signtool.exe"
  foreach ($p in $packages) {
    & $signtool sign /fd SHA256 /a /f $PfxPath /p $PfxPassword $p
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $p" }
  }
} else {
  Write-Host "Unsigned packages (Store signs on submission). For sideload testing pass -PfxPath with a certificate whose subject is '$Publisher'."
}
$packages | ForEach-Object { Get-Item $_ | Select-Object FullName, Length }
