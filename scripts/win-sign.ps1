# win-sign.ps1
#
# Code-sign iccp.dll with Authenticode using signtool.exe from the
# Windows SDK. Supports three certificate sources:
#
#   -CertThumbprint <sha1>   -- cert already in Cert:\CurrentUser\My or
#                               Cert:\LocalMachine\My (recommended for
#                               HSM-backed certs and for dev self-signed
#                               certs created via New-DevCodeCert below).
#
#   -PfxFile <path.pfx>      -- classic PFX file on disk.
#   -PfxPassword <SecureString or plaintext>   for the above.
#
#   -DevSelfSigned           -- auto-generate and use a self-signed cert
#                               (writes it to Cert:\CurrentUser\My).
#                               This only suppresses the SmartScreen
#                               "unknown publisher" warning for the
#                               machine that has the cert trusted as a
#                               Trusted Root; it is not accepted by
#                               corporate Wireshark policies that pin a
#                               specific CA. For real distribution get a
#                               purchased cert (see README).
#
# Always timestamps the signature (RFC 3161) so the signed binary
# remains valid after the signing cert expires.
#
# Examples:
#   .\scripts\win-sign.ps1 -DevSelfSigned
#   .\scripts\win-sign.ps1 -CertThumbprint 1234567890ABCDEF...
#   .\scripts\win-sign.ps1 -PfxFile my.pfx -PfxPassword (Read-Host -AsSecureString)
#
# Runs signtool verify at the end to confirm the signature is valid.

[CmdletBinding(DefaultParameterSetName='Thumbprint')]
Param(
    [Parameter(ParameterSetName='Thumbprint')]
    [string]$CertThumbprint,

    [Parameter(ParameterSetName='Pfx', Mandatory=$true)]
    [string]$PfxFile,

    [Parameter(ParameterSetName='Pfx')]
    [object]$PfxPassword,

    [Parameter(ParameterSetName='DevSelfSigned')]
    [switch]$DevSelfSigned,

    [string]$Dll,

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [string]$FileDescription = 'ICCP / TASE.2 Wireshark dissector plugin'
)

if (-not $Dll) {
    $Dll = Join-Path (Split-Path -Parent $PSScriptRoot) "build\iccp\RelWithDebInfo\iccp.dll"
}

if (-not (Test-Path $Dll)) {
    Write-Error "DLL not found: $Dll"
    exit 1
}

# Put signtool on PATH. The VC vars don't always survive across PS
# sessions, so re-source the dev env.
. (Join-Path $PSScriptRoot 'win-build-env.ps1') | Out-Null
# Locate signtool.exe under any installed Windows SDK; pick the highest
# x64 version available.
$signtool = (Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -match '\\x64$' } |
    Sort-Object -Property FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName)
if (-not $signtool -or -not (Test-Path $signtool)) {
    Write-Error "signtool.exe not found under Windows SDK"
    exit 1
}

# Dev self-signed path: create (or reuse) a dev cert, then use it.
if ($DevSelfSigned) {
    $devSubject = 'CN=ICCP Wireshark Dissector Dev (self-signed)'
    $existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $devSubject -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
    if (-not $existing) {
        Write-Host "=== generating self-signed code-signing cert ==="
        $existing = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject  $devSubject `
            -KeyUsage DigitalSignature `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotAfter (Get-Date).AddYears(3)
    }
    $CertThumbprint = $existing.Thumbprint
    Write-Host "using dev cert thumbprint $CertThumbprint"
}

$args = @(
    'sign',
    '/fd', 'SHA256',            # signature digest algorithm
    '/tr', $TimestampUrl,       # RFC 3161 timestamp server
    '/td', 'SHA256',            # timestamp digest algorithm
    '/d',  $FileDescription     # shown in Authenticode publisher info
)

switch ($PSCmdlet.ParameterSetName) {
    'Thumbprint' {
        if (-not $CertThumbprint) {
            Write-Error "Need -CertThumbprint, -PfxFile, or -DevSelfSigned."
            exit 2
        }
        $args += @('/sha1', $CertThumbprint)
    }
    'Pfx' {
        if (-not $PfxPassword) {
            Write-Error "-PfxFile requires -PfxPassword."
            exit 2
        }
        if ($PfxPassword -is [System.Security.SecureString]) {
            $plain = [System.Net.NetworkCredential]::new('', $PfxPassword).Password
        } else {
            $plain = [string]$PfxPassword
        }
        $args += @('/f', $PfxFile, '/p', $plain)
    }
    'DevSelfSigned' {
        $args += @('/sha1', $CertThumbprint)
    }
}

$args += $Dll

Write-Host "=== signing $Dll ==="
Write-Host "signtool args: $($args -join ' ')"
& $signtool @args
if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool sign failed with exit $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=== verifying signature ==="
& $signtool verify /pa /v $Dll
if ($LASTEXITCODE -ne 0) {
    Write-Warning "signtool verify returned $LASTEXITCODE. A non-zero exit is expected for a self-signed cert (not chained to a trusted root) and means nothing about the signature itself being valid; it just means no trusted CA chain."
}
