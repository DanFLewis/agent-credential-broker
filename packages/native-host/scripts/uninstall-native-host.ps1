<#
.SYNOPSIS
  Removes what install-native-host.ps1 created: registry keys, host manifest and wrapper.
#>
$ErrorActionPreference = 'Stop'
$hostName = 'com.acb.broker'

foreach ($key in "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName",
                 "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName") {
  if (Test-Path $key) { Remove-Item -Path $key -Force; Write-Host "Removed $key" }
}

$base = if ($env:ACB_HOME) { $env:ACB_HOME } else { Join-Path $env:LOCALAPPDATA 'acb' }
$dir = Join-Path $base 'native-host'
foreach ($f in "$hostName.json", 'acb-native-host.cmd') {
  $p = Join-Path $dir $f
  if (Test-Path $p) { Remove-Item -Path $p -Force; Write-Host "Removed $p" }
}
