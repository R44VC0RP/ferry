# Installs ferry on Windows: downloads the release binary, checks it against
# the published checksum, and runs `ferry install` (a task that starts at boot
# and a firewall rule). Run in an Administrator PowerShell:
#
#   irm https://raw.githubusercontent.com/R44VC0RP/ferry/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5 does not offer TLS 1.2 by default; GitHub requires it.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    throw 'ferry: run this in an Administrator PowerShell. It adds a boot task and a firewall rule.'
}

$base = 'https://github.com/R44VC0RP/ferry/releases/latest/download'
$asset = 'ferry-windows-x64.exe'
$dir = Join-Path $env:TEMP ('ferry-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
    $exe = Join-Path $dir 'ferry.exe'
    $sums = Join-Path $dir 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile $exe
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile $sums

    $line = Get-Content $sums | Where-Object { ($_ -split '\s+')[1] -eq $asset } | Select-Object -First 1
    $want = if ($line) { ($line -split '\s+')[0].ToLower() } else { '' }
    $got = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if (-not $want -or $want -ne $got) {
        throw "ferry: checksum mismatch for $asset, not installing."
    }

    & $exe install
}
finally {
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
}
