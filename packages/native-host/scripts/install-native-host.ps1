<#
.SYNOPSIS
  Registers the Agent Credential Broker native messaging host for Chrome and Edge (current user only).
.DESCRIPTION
  Writes %LOCALAPPDATA%\acb\native-host\com.acb.broker.json plus an acb-native-host.cmd wrapper, and sets
  the default value of HKCU\Software\{Google\Chrome,Microsoft\Edge}\NativeMessagingHosts\com.acb.broker.
  Build the native host first (dist\index.js must exist). Remove with uninstall-native-host.ps1.
#>
[CmdletBinding()]
param(
  # Defaults to the ID derived from the key in packages\extension\manifest.json.
  [string]$ExtensionId = '',
  [string]$NodePath = ''
)
$ErrorActionPreference = 'Stop'

# Resolved here, not in the param default: Windows PowerShell 5.1 leaves $PSScriptRoot empty there.
if (-not $ExtensionId) {
  $ExtensionId = (Get-Content -Raw (Join-Path $PSScriptRoot '..\..\extension\EXTENSION_ID.txt')).Trim()
}

if ($ExtensionId -notmatch '^[a-p]{32}$') { throw "Invalid extension id: $ExtensionId" }

$hostName = 'com.acb.broker'
$entry = (Resolve-Path (Join-Path $PSScriptRoot '..\dist\index.js') -ErrorAction SilentlyContinue)
if (-not $entry) { throw 'packages\native-host\dist\index.js not found. Build the native host first.' }

# Chrome launches the host with a minimal environment, so pin the node binary now.
if (-not $NodePath) { $NodePath = (Get-Command node -ErrorAction Stop).Source }

$base = if ($env:ACB_HOME) { $env:ACB_HOME } else { Join-Path $env:LOCALAPPDATA 'acb' }
$dir = Join-Path $base 'native-host'
New-Item -ItemType Directory -Force $dir | Out-Null

$cmdPath = Join-Path $dir 'acb-native-host.cmd'
Set-Content -Path $cmdPath -Encoding ascii -Value "@`"$NodePath`" `"$($entry.Path)`" %*"

$manifestPath = Join-Path $dir "$hostName.json"
$manifest = [ordered]@{
  name            = $hostName
  description     = 'Agent Credential Broker native host'
  path            = $cmdPath
  type            = 'stdio'
  allowed_origins = @("chrome-extension://$ExtensionId/")
}
# Chrome rejects a manifest with a UTF-8 BOM, so write it without one.
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

foreach ($key in "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName",
                 "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName") {
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name '(default)' -Value $manifestPath
}

Write-Host "Installed native host manifest: $manifestPath"
Write-Host "Allowed extension: chrome-extension://$ExtensionId/"
