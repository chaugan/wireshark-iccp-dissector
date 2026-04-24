# win-build-wireshark.ps1
#
# Build and install Wireshark 4.2 from source on Windows so that
# WiresharkConfig.cmake is available for the plugin build. This is a
# one-time setup: after this succeeds, win-build-plugin.ps1 can rebuild
# the plugin in under a minute.
#
# Steps:
#   1. Clone (if not already present) wireshark source at release-4.2
#      branch.
#   2. Run tools\win-setup.ps1 to download prebuilt dep libraries into
#      C:\Development\wireshark-x64-libs-4.2.
#   3. CMake-configure a minimal Wireshark build (no Qt GUI, no extra
#      extcap tools -- we only need libwireshark / libwsutil / libwiretap
#      and the cmake package).
#   4. Build at RelWithDebInfo.
#   5. Install the default + "Development" components to the chosen
#      prefix so that WiresharkConfig.cmake + headers + import libs all
#      land in one place.
#
# Total wall time on a modern box: ~5 min download + ~3 min build.

[CmdletBinding()]
Param(
    [string]$SourceDir  = 'C:\dev\wireshark',
    [string]$BuildDir   = 'C:\dev\wsbuild64',
    [string]$InstallDir = 'C:\dev\ws-install',
    [string]$LibsDir    = 'C:\Development\wireshark-x64-libs-4.2',
    [string]$Branch     = 'release-4.2',
    [string]$Config     = 'RelWithDebInfo',

    # -WithGui flips BUILD_wireshark=ON and builds the full Qt UI. We
    # auto-discover Qt6 under C:\Qt\<version>\msvc*_64\ but you can
    # override via -Qt6Dir. Leaves BUILD_wireshark=OFF when not given,
    # which keeps the build fast and Qt-free for pure plugin-dev loops.
    [switch]$WithGui,
    [string]$Qt6Dir
)

. (Join-Path $PSScriptRoot 'win-build-env.ps1') | Out-Null

# 1. Clone source
if (-not (Test-Path $SourceDir)) {
    Write-Host "=== clone $Branch into $SourceDir ==="
    git clone --depth 1 --branch $Branch https://github.com/wireshark/wireshark.git $SourceDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "=== source already present at $SourceDir ==="
    git -C $SourceDir log -1 --oneline
}

# 2. Win-setup (prebuilt deps)
New-Item -ItemType Directory -Path $LibsDir -Force | Out-Null
if (-not (Test-Path (Join-Path $LibsDir 'current_tag.txt'))) {
    Write-Host ""
    Write-Host "=== download prebuilt deps into $LibsDir ==="
    & (Join-Path $SourceDir 'tools\win-setup.ps1') -Destination $LibsDir -Platform x64
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "=== prebuilt deps already present at $LibsDir ==="
}

$env:WIRESHARK_BASE_DIR = Split-Path -Parent $LibsDir

# 3. Configure
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
Set-Location $BuildDir

# Resolve Qt6 location when building the GUI.
if ($WithGui -and -not $Qt6Dir) {
    Write-Host ""
    Write-Host "=== -WithGui: auto-discovering Qt6 under C:\Qt\* ==="
    $candidates = Get-ChildItem -Path 'C:\Qt' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+(\.\d+)?$' } |
        Sort-Object { [version]$_.Name } -Descending
    foreach ($c in $candidates) {
        $msvc = Get-ChildItem -Path $c.FullName -Directory -Filter 'msvc*_64' -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending | Select-Object -First 1
        if ($msvc -and (Test-Path (Join-Path $msvc.FullName 'lib\cmake\Qt6\Qt6Config.cmake'))) {
            $Qt6Dir = $msvc.FullName
            Write-Host "using Qt6 at $Qt6Dir"
            break
        }
    }
    if (-not $Qt6Dir) {
        Write-Error "-WithGui requested but no MSVC Qt6 found under C:\Qt\*\msvc*_64\. Pass -Qt6Dir explicitly."
        exit 2
    }
}

if (-not (Test-Path 'CMakeCache.txt')) {
    Write-Host ""
    if ($WithGui) {
        Write-Host "=== CMake configure (full GUI build, Qt6=$Qt6Dir) ==="
    } else {
        Write-Host "=== CMake configure (libs-only, no Qt) ==="
    }

    # BUILD_* flags. When -WithGui is passed we only skip the extcap
    # helpers (sshdump etc.); when it's not, we also skip the Qt GUI,
    # tshark/dumpcap/etc., cutting the build down to ~3 min.
    $cmakeArgs = @(
        '-G', 'Visual Studio 17 2022', '-A', 'x64',
        "-DWIRESHARK_BASE_DIR=$(Split-Path -Parent $LibsDir)",
        '-DDISABLE_WERROR=ON',
        '-DBUILD_androiddump=OFF',
        '-DBUILD_sshdump=OFF',
        '-DBUILD_ciscodump=OFF',
        '-DBUILD_udpdump=OFF',
        '-DBUILD_wifidump=OFF',
        '-DBUILD_dpauxmon=OFF',
        '-DBUILD_randpktdump=OFF',
        '-DBUILD_etwdump=OFF'
    )
    if ($WithGui) {
        # CMake's VS generator doesn't always auto-discover the Windows
        # SDK lib path that find_library uses. Wireshark 4.6+ calls
        # find_library(Bcrypt_LIBRARY ...) with no HINTS, which fails
        # if the SDK lib dir isn't on CMAKE_LIBRARY_PATH. Handle it.
        $sdkRoot = 'C:\Program Files (x86)\Windows Kits\10\Lib'
        $sdkVer  = (Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1).Name
        if ($sdkVer) {
            $sdkLib = "$sdkRoot\$sdkVer\um\x64"
            $cmakeArgs += @(
                '-DBUILD_wireshark=ON',
                "-DCMAKE_PREFIX_PATH=$Qt6Dir",
                "-DCMAKE_LIBRARY_PATH=$sdkLib",
                "-DBcrypt_LIBRARY=$sdkLib\bcrypt.lib"
            )
        } else {
            $cmakeArgs += @(
                '-DBUILD_wireshark=ON',
                "-DCMAKE_PREFIX_PATH=$Qt6Dir"
            )
        }
    } else {
        $cmakeArgs += @(
            '-DBUILD_wireshark=OFF',
            '-DBUILD_logwolf=OFF',
            '-DBUILD_rawshark=OFF',
            '-DBUILD_randpkt=OFF',
            '-DBUILD_dftest=OFF',
            '-DBUILD_sharkd=OFF'
        )
    }
    $cmakeArgs += $SourceDir

    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "=== reusing existing CMake cache in $BuildDir ==="
}

# 4. Build
Write-Host ""
Write-Host "=== build Wireshark libs ($Config) ==="
cmake --build . --config $Config --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 5. Install (both default and Development components)
Write-Host ""
Write-Host "=== install to $InstallDir ==="
cmake --install . --config $Config --prefix $InstallDir
cmake --install . --config $Config --prefix $InstallDir --component Development
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$wsConfig = Join-Path $InstallDir 'cmake\WiresharkConfig.cmake'
if (-not (Test-Path $wsConfig)) {
    Write-Error "WiresharkConfig.cmake not found after install. Something went wrong."
    exit 1
}

Write-Host ""
Write-Host "=== done ==="
Write-Host "Wireshark 4.2 install prefix: $InstallDir"
Write-Host "WiresharkConfig.cmake:        $wsConfig"
Write-Host "tshark runtime (for testing): $BuildDir\run\$Config\tshark.exe"
Write-Host ""
Write-Host "Next step:"
Write-Host "  .\scripts\win-build-plugin.ps1 -WiresharkInstall $InstallDir"
