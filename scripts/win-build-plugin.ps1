# win-build-plugin.ps1
#
# Build the ICCP / TASE.2 Wireshark plugin on Windows against an
# installed Wireshark 4.2 dev tree. The Wireshark install prefix is
# either passed as the first argument or picked up from the environment
# variable WIRESHARK_INSTALL_DIR. Default: C:\dev\ws-install.
#
# Prerequisites (all already installed for this repo's dev loop):
#   - Visual Studio 2022 Build Tools with the "Desktop development with
#     C++" workload (MSVC 14.43+, Windows 11 SDK)
#   - CMake, Strawberry Perl, winflexbison, Python 3, Git
#   - A built + installed Wireshark 4.2 dev tree that contains
#     WiresharkConfig.cmake (see scripts/win-build-wireshark.ps1)
#
# Outputs iccp.dll to C:\dev\iccp-build\RelWithDebInfo\iccp.dll and
# installs it into the user's Wireshark plugin directory
# %APPDATA%\Wireshark\plugins\4.2\epan\iccp.dll.

[CmdletBinding()]
Param(
    [string]$WiresharkInstall = $env:WIRESHARK_INSTALL_DIR,
    [string]$PluginBuild      = 'C:\dev\iccp-build',
    [string]$Config           = 'RelWithDebInfo',
    [switch]$NoInstall
)

if (-not $WiresharkInstall -or $WiresharkInstall -eq '') {
    $WiresharkInstall = 'C:\dev\ws-install'
}

$pluginSrc = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'win-build-env.ps1') | Out-Null

if (-not (Test-Path (Join-Path $WiresharkInstall 'cmake\WiresharkConfig.cmake'))) {
    Write-Error "WiresharkConfig.cmake not found under $WiresharkInstall. Build and install Wireshark 4.2 first (see scripts/win-build-wireshark.ps1)."
    exit 1
}

New-Item -ItemType Directory -Path $PluginBuild -Force | Out-Null
Set-Location $PluginBuild

Write-Host ""
Write-Host "=== configure (Wireshark_DIR=$WiresharkInstall\cmake) ==="
# CMake 4.x no longer searches <prefix>/cmake/<pkg>Config.cmake by
# default -- only <prefix>/lib/cmake/<pkg>/ or <prefix>/<pkg>*/.
# Wireshark installs to <prefix>/cmake/ on Windows, so we point
# Wireshark_DIR at it directly instead of relying on CMAKE_PREFIX_PATH.
cmake -G 'Visual Studio 17 2022' -A x64 `
    -DWireshark_DIR="$WiresharkInstall\cmake" `
    $pluginSrc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== build (config $Config) ==="
cmake --build . --config $Config
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dll = Join-Path $PluginBuild "$Config\iccp.dll"
if (-not (Test-Path $dll)) {
    Write-Error "iccp.dll not produced at $dll"
    exit 1
}

$len = (Get-Item $dll).Length
Write-Host ""
Write-Host "=== produced $dll ($len bytes) ==="

if (-not $NoInstall) {
    $userPluginDir = "$env:APPDATA\Wireshark\plugins\4.2\epan"
    New-Item -ItemType Directory -Path $userPluginDir -Force | Out-Null
    Copy-Item $dll -Destination $userPluginDir -Force
    Write-Host "installed to $userPluginDir\iccp.dll"
}
