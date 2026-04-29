# win-portable-build.ps1
#
# Build iccp.dll on a Windows box that has NO admin access, NO Visual Studio,
# NO Windows SDK, and NO Wireshark installed. Everything is downloaded into
# a per-user directory and run from there.
#
# Inputs (everything has a default; override via flags or env):
#   -BuildRoot         Where to stage tools and build trees. Default $HOME\.iccp-build
#   -WiresharkBranch   Wireshark source branch (default release-4.2)
#   -WiresharkDevTree  Path to a pre-built Wireshark install tree. If given, the
#                      Wireshark source build (Phase 2) is skipped entirely and
#                      this tree is used as Wireshark_DIR's parent. Useful when
#                      Phase 2 hits a Perl/flex issue or is too slow.
#   -PluginVersion     Wireshark major.minor for the install path under
#                      %APPDATA%\Wireshark\plugins\<X.Y>\epan. Auto-derived
#                      from the dev tree when omitted.
#   -SkipInstall       Build iccp.dll but don't copy it into %APPDATA%.
#   -ForceMSVC         Re-download MSVC even if msvc\ already exists.
#   -ForceWireshark    Re-build Wireshark even if WiresharkConfig.cmake exists.
#
# Phases:
#   1) Bootstrap portable toolchain (MSVC, SDK, CMake, Ninja, Perl, Python check)
#   2) Build minimal Wireshark dev tree (one-time, cached)
#   3) Build iccp.dll and (optionally) install it
#
# All phases are idempotent: rerunning skips work that's already done.

[CmdletBinding()]
Param(
    [string]$BuildRoot        = (Join-Path $HOME '.iccp-build'),
    [string]$WiresharkBranch  = 'release-4.2',
    [string]$WiresharkDevTree,
    [string]$PluginVersion,
    [switch]$SkipInstall,
    [switch]$ForceMSVC,
    [switch]$ForceWireshark
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Pinned tool versions. Bump deliberately -- these download URLs are the
# only thing that ties this script to a specific point-in-time toolchain,
# and a stable pin makes runs reproducible across machines.
$CMakeVersion = '3.30.5'
$NinjaVersion = '1.12.1'
$PerlVersion  = '5.32.1.1'
# 2.5.25 has a regression that fails to parse Wireshark's
# wiretap/candump_scanner.l ("extern_stdin:922: ERROR: end of file
# in string"). 2.5.24 doesn't.
$WinFlexBisonVersion = '2.5.24'

# CMake cmake-<ver>-windows-x86_64.zip extracts to that prefix.
$CMakeZipUrl  = "https://github.com/Kitware/CMake/releases/download/v$CMakeVersion/cmake-$CMakeVersion-windows-x86_64.zip"
$CMakeZipDir  = "cmake-$CMakeVersion-windows-x86_64"

$NinjaZipUrl  = "https://github.com/ninja-build/ninja/releases/download/v$NinjaVersion/ninja-win.zip"

# Strawberry Perl ships a portable zip variant alongside the MSI.
$PerlZipUrl   = "https://strawberryperl.com/download/$PerlVersion/strawberry-perl-$PerlVersion-64bit-portable.zip"

# winflexbison provides win_flex.exe / win_bison.exe -- Wireshark's
# FindLEX/FindBISON look for these names. Portable zip, no installer.
$WinFlexBisonZipUrl = "https://github.com/lexxmark/winflexbison/releases/download/v$WinFlexBisonVersion/win_flex_bison-$WinFlexBisonVersion.zip"

# mmozeiko's portable-msvc.py: downloads VS Build Tools components and a
# Windows SDK directly from Microsoft's CDN, no installer or admin.
$PortableMsvcUrl = 'https://gist.githubusercontent.com/mmozeiko/7f3162ec2988e81e56d5c4e22cde9977/raw/portable-msvc.py'

$repoRoot     = Split-Path -Parent $PSScriptRoot
$toolsDir     = Join-Path $BuildRoot 'tools'
$msvcDir      = Join-Path $BuildRoot 'msvc'
$cmakeRoot    = Join-Path $toolsDir  'cmake'
$ninjaDir     = Join-Path $toolsDir  'ninja'
$perlRoot     = Join-Path $toolsDir  'perl'
$flexBisonDir = Join-Path $toolsDir  'winflexbison'
# tools\win-setup.ps1 validates that the destination dir name matches
# wireshark-<platform>-libs-<minor> (e.g. wireshark-x64-libs-4.2).
# Anything else fails with a ValidateScript error before downloading.
if ($WiresharkBranch -match '^release-(\d+\.\d+)$') {
    $wsMinor = $Matches[1]
} else {
    Write-Error "WiresharkBranch '$WiresharkBranch' does not match release-X.Y; pass an explicit branch."
    exit 2
}
# Version-suffix every Wireshark-specific path so back-to-back builds
# of 4.2 / 4.4 / 4.6 reuse the same toolchain ($BuildRoot\msvc, etc.)
# without clobbering each other's source / build / install trees.
$wsSrcDir      = Join-Path $BuildRoot "ws-src-$wsMinor"
$wsBuildDir    = Join-Path $BuildRoot "ws-build-$wsMinor"
$wsInstallDir  = Join-Path $BuildRoot "ws-install-$wsMinor"
$wsCacheParent = Join-Path $BuildRoot 'ws-cache'
$wsCacheDir    = Join-Path $wsCacheParent "wireshark-x64-libs-$wsMinor"
$pluginBuild   = Join-Path $BuildRoot "plugin-build-$wsMinor"

New-Item -ItemType Directory -Path $BuildRoot, $toolsDir -Force | Out-Null

function Write-Phase($msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

function Download-File($url, $dest) {
    if (Test-Path $dest) { return }
    Write-Host "downloading $url"
    $tmp = "$dest.partial"
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    Move-Item -Force $tmp $dest
}

function Expand-If-Missing($zipPath, $destDir, $sentinel) {
    if (Test-Path $sentinel) { return }
    Write-Host "extracting $(Split-Path -Leaf $zipPath) -> $destDir"
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $destDir -Force
}

function Need-Python() {
    $py = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3.exe -ErrorAction SilentlyContinue }
    if (-not $py) {
        Write-Error "python is required (for portable-msvc.py). Mambaforge ships one -- make sure it's on PATH."
        exit 2
    }
    return $py.Source
}

# ----------------------------------------------------------------------
# Phase 1: portable toolchain
# ----------------------------------------------------------------------
Write-Phase "Phase 1: bootstrap portable toolchain into $BuildRoot"

# 1a. Portable MSVC + SDK (the slow one -- ~2 GB download)
$msvcSentinel = Join-Path $msvcDir 'VC\Tools\MSVC'
if ($ForceMSVC -and (Test-Path $msvcDir)) {
    Write-Host "removing existing $msvcDir (-ForceMSVC)"
    Remove-Item -Recurse -Force $msvcDir
}
if (Test-Path $msvcSentinel) {
    Write-Host "MSVC already present at $msvcDir"
} else {
    $py = Need-Python
    $portableMsvcPy = Join-Path $toolsDir 'portable-msvc.py'
    Download-File $PortableMsvcUrl $portableMsvcPy

    Write-Host "running portable-msvc.py (this downloads ~2 GB of MSVC + SDK)"
    Push-Location $BuildRoot
    try {
        # portable-msvc.py drops VC\ and Windows Kits\ into the cwd. We
        # then move them under msvc\ so this script's path layout matches
        # the directory layout described in the plan header.
        & $py $portableMsvcPy --accept-license
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        New-Item -ItemType Directory -Path $msvcDir -Force | Out-Null
        foreach ($name in 'VC','Windows Kits') {
            if (Test-Path (Join-Path $BuildRoot $name)) {
                Move-Item -Force (Join-Path $BuildRoot $name) (Join-Path $msvcDir $name)
            }
        }
    } finally {
        Pop-Location
    }
}

# Resolve the actual MSVC + SDK leaf paths (versions are nested dirs).
$msvcToolsRoot = Join-Path $msvcDir 'VC\Tools\MSVC'
$msvcVer = (Get-ChildItem $msvcToolsRoot -Directory |
            Sort-Object { [version]$_.Name } -Descending |
            Select-Object -First 1).Name
if (-not $msvcVer) { Write-Error "no MSVC version dir under $msvcToolsRoot"; exit 1 }
$msvcBin     = Join-Path $msvcToolsRoot "$msvcVer\bin\Hostx64\x64"
$msvcInclude = Join-Path $msvcToolsRoot "$msvcVer\include"
$msvcLib     = Join-Path $msvcToolsRoot "$msvcVer\lib\x64"

$sdkRoot = Join-Path $msvcDir 'Windows Kits\10'
if (-not (Test-Path $sdkRoot)) {
    # Older portable-msvc layouts dropped the SDK at the top level.
    $sdkRoot = Join-Path $msvcDir 'Windows Kits'
}
$sdkIncRoot = Join-Path $sdkRoot 'Include'
$sdkLibRoot = Join-Path $sdkRoot 'Lib'
$sdkVer = (Get-ChildItem $sdkIncRoot -Directory |
           Sort-Object { [version]$_.Name } -Descending |
           Select-Object -First 1).Name
if (-not $sdkVer) { Write-Error "no SDK version dir under $sdkIncRoot"; exit 1 }
$sdkInclude = Join-Path $sdkIncRoot $sdkVer
$sdkLib     = Join-Path $sdkLibRoot $sdkVer
$sdkBin     = Join-Path $sdkRoot   "bin\$sdkVer\x64"

# Redist DLLs (vcruntime140.dll, ucrtbase.dll, ...). Without these on
# PATH, CMake's try_run-based checks fail silently because the test
# exe can't locate its CRT at startup. Wireshark's HAVE_C99_VSNPRINTF
# is one such check.
$msvcRedistRoot = Join-Path $msvcDir 'VC\Redist\MSVC'
$msvcRedistDir  = $null
if (Test-Path $msvcRedistRoot) {
    $rver = (Get-ChildItem $msvcRedistRoot -Directory |
             Sort-Object { [version]$_.Name } -Descending |
             Select-Object -First 1).Name
    if ($rver) {
        $crt = Get-ChildItem (Join-Path $msvcRedistRoot "$rver\x64") -Directory -Filter 'Microsoft.VC*.CRT' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($crt) { $msvcRedistDir = $crt.FullName }
    }
}
$ucrtRedistDir = Join-Path $sdkRoot "Redist\$sdkVer\ucrt\DLLs\x64"
if (-not (Test-Path $ucrtRedistDir)) {
    $ucrtRedistDir = Join-Path $sdkRoot 'Redist\ucrt\DLLs\x64'
}
if (-not (Test-Path $ucrtRedistDir)) { $ucrtRedistDir = $null }

# Debug CRT (vcruntime140d.dll, msvcp140d.dll, ucrtbased.dll). Needed
# because CMake's try_compile/try_run defaults to Debug config when
# CMAKE_TRY_COMPILE_CONFIGURATION isn't set, and Wireshark's
# HAVE_C99_VSNPRINTF probe is a try_run -- the test exe needs the
# debug CRT to start up.
$msvcDebugDir = $null
if ($msvcRedistRoot -and (Test-Path $msvcRedistRoot)) {
    $rver2 = (Get-ChildItem $msvcRedistRoot -Directory |
              Sort-Object { [version]$_.Name } -Descending |
              Select-Object -First 1).Name
    $cand = Get-ChildItem (Join-Path $msvcRedistRoot "$rver2\debug_nonredist\x64") -Directory -Filter 'Microsoft.VC*.DebugCRT' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if ($cand) { $msvcDebugDir = $cand.FullName }
}
$ucrtDebugDir = Join-Path $sdkRoot "bin\$sdkVer\x64\ucrt"
if (-not (Test-Path $ucrtDebugDir)) { $ucrtDebugDir = $null }

# 1b. Portable CMake
$cmakeBin = Join-Path $cmakeRoot "$CMakeZipDir\bin"
if (-not (Test-Path (Join-Path $cmakeBin 'cmake.exe'))) {
    $zip = Join-Path $toolsDir "cmake-$CMakeVersion.zip"
    Download-File $CMakeZipUrl $zip
    Expand-If-Missing $zip $cmakeRoot (Join-Path $cmakeBin 'cmake.exe')
} else {
    Write-Host "CMake already present at $cmakeBin"
}

# 1c. Ninja
if (-not (Test-Path (Join-Path $ninjaDir 'ninja.exe'))) {
    $zip = Join-Path $toolsDir "ninja-$NinjaVersion.zip"
    Download-File $NinjaZipUrl $zip
    Expand-If-Missing $zip $ninjaDir (Join-Path $ninjaDir 'ninja.exe')
} else {
    Write-Host "Ninja already present at $ninjaDir"
}

# 1d. Strawberry Perl portable (Wireshark's ASN.1 generator needs perl)
$perlBin = Join-Path $perlRoot 'perl\bin'
if (-not (Test-Path (Join-Path $perlBin 'perl.exe'))) {
    $zip = Join-Path $toolsDir "strawberry-perl-$PerlVersion.zip"
    Download-File $PerlZipUrl $zip
    Expand-If-Missing $zip $perlRoot (Join-Path $perlBin 'perl.exe')
} else {
    Write-Host "Strawberry Perl already present at $perlRoot"
}
$perlCBin = Join-Path $perlRoot 'c\bin'

# 1e. winflexbison (lex/yacc, needed by Wireshark for tokenizers).
# Version-stamp the install dir so bumping $WinFlexBisonVersion forces
# a fresh extract -- 2.5.25 vs 2.5.24 behaves differently and we don't
# want a stale cached copy to silently override the pin.
$fbVersionStamp = Join-Path $flexBisonDir ".version-$WinFlexBisonVersion"
if (-not (Test-Path $fbVersionStamp) -or -not (Test-Path (Join-Path $flexBisonDir 'win_flex.exe'))) {
    if (Test-Path $flexBisonDir) { Remove-Item -Recurse -Force $flexBisonDir }
    $zip = Join-Path $toolsDir "winflexbison-$WinFlexBisonVersion.zip"
    if (-not (Test-Path $zip)) { Download-File $WinFlexBisonZipUrl $zip }
    New-Item -ItemType Directory -Path $flexBisonDir -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $flexBisonDir -Force
    New-Item -ItemType File -Path $fbVersionStamp -Force | Out-Null
} else {
    Write-Host "winflexbison $WinFlexBisonVersion already present at $flexBisonDir"
}

# 1e. Compose the env that every CMake / cl.exe invocation below depends on.
# This is what vcvars64.bat normally does -- we do it by hand because we have
# no vcvars and no Visual Studio to host one.
$origPath    = $env:PATH
$origInclude = $env:INCLUDE
$origLib     = $env:LIB

$pathPrefix = @($msvcBin, $sdkBin, $cmakeBin, $ninjaDir, $perlBin, $perlCBin, $flexBisonDir)
if ($msvcRedistDir) { $pathPrefix += $msvcRedistDir }
if ($ucrtRedistDir) { $pathPrefix += $ucrtRedistDir }
if ($msvcDebugDir)  { $pathPrefix += $msvcDebugDir }
if ($ucrtDebugDir)  { $pathPrefix += $ucrtDebugDir }
$env:PATH    = ($pathPrefix -join ';') + ";$env:PATH"
$env:INCLUDE = "$msvcInclude;$sdkInclude\ucrt;$sdkInclude\um;$sdkInclude\shared;$sdkInclude\winrt;$sdkInclude\cppwinrt"
$env:LIB     = "$msvcLib;$sdkLib\ucrt\x64;$sdkLib\um\x64"
# CMake's Ninja generator picks the compiler from CC / CXX when the env
# is populated like this -- no toolchain file needed.
$env:CC      = Join-Path $msvcBin 'cl.exe'
$env:CXX     = $env:CC

Write-Host "MSVC      $msvcVer  ($msvcBin)"
Write-Host "SDK       $sdkVer   ($sdkInclude)"
Write-Host "VC redist $msvcRedistDir"
Write-Host "UCRT      $ucrtRedistDir"
Write-Host "VC debug  $msvcDebugDir"
Write-Host "UCRT dbg  $ucrtDebugDir"
Write-Host "CMake     $((& cmake --version | Select-Object -First 1))"
Write-Host "Ninja     $((& ninja --version))"
Write-Host "Perl      $((& perl --version | Select-String -Pattern 'This is perl' | ForEach-Object { $_.ToString().Trim() }))"

# ----------------------------------------------------------------------
# Phase 2: minimal Wireshark dev tree
# ----------------------------------------------------------------------
$wsConfigCmake = Join-Path $wsInstallDir 'cmake\WiresharkConfig.cmake'

if ($WiresharkDevTree) {
    Write-Phase "Phase 2: using provided Wireshark dev tree at $WiresharkDevTree"
    $wsInstallDir  = (Resolve-Path $WiresharkDevTree).Path
    $wsConfigCmake = Join-Path $wsInstallDir 'cmake\WiresharkConfig.cmake'
    if (-not (Test-Path $wsConfigCmake)) {
        Write-Error "WiresharkConfig.cmake not found under $wsInstallDir\cmake. Pass a valid dev tree."
        exit 1
    }
} elseif ((Test-Path $wsConfigCmake) -and -not $ForceWireshark) {
    Write-Phase "Phase 2: Wireshark dev tree already built at $wsInstallDir (skip)"
} else {
    Write-Phase "Phase 2: build minimal Wireshark dev tree"

    if (-not (Test-Path $wsSrcDir)) {
        Write-Host "cloning wireshark $WiresharkBranch (shallow)"
        git clone --depth 1 --branch $WiresharkBranch https://github.com/wireshark/wireshark.git $wsSrcDir
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Host "Wireshark source already cloned at $wsSrcDir"
        git -C $wsSrcDir log -1 --oneline
    }

    # Wireshark 4.2 / 4.4 ship tools\win-setup.ps1 to pre-fetch MSVC-
    # compatible deps (glib, c-ares, gnutls, lua, ...) into the libs
    # dir. 4.6 dropped that script in favour of in-CMake artifact
    # fetching (cmake/modules/FetchArtifacts.cmake), driven by the same
    # WIRESHARK_BASE_DIR but pulled at configure time. Run win-setup.ps1
    # only if it exists.
    New-Item -ItemType Directory -Path $wsCacheDir -Force | Out-Null
    $winSetup = Join-Path $wsSrcDir 'tools\win-setup.ps1'
    if (Test-Path $winSetup) {
        if (-not (Test-Path (Join-Path $wsCacheDir 'current_tag.txt'))) {
            Write-Host "fetching prebuilt Wireshark deps via tools\win-setup.ps1"
            & $winSetup -Destination $wsCacheDir -Platform x64
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } else {
            Write-Host "prebuilt deps already present at $wsCacheDir"
        }
    } else {
        Write-Host "tools\win-setup.ps1 not in this Wireshark version; CMake's FetchArtifacts.cmake will pull deps at configure time"
    }
    # WIRESHARK_BASE_DIR is the parent of wireshark-x64-libs-<minor>;
    # Wireshark's CMakeLists joins it with the libs dir name itself.
    $env:WIRESHARK_BASE_DIR = $wsCacheParent

    New-Item -ItemType Directory -Path $wsBuildDir -Force | Out-Null
    Push-Location $wsBuildDir
    try {
        if (-not (Test-Path 'CMakeCache.txt') -or $ForceWireshark) {
            Write-Host "configuring (Ninja, RelWithDebInfo, libs only)"
            $args = @(
                '-G', 'Ninja',
                '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
                # Force probe exes to release CRT -- otherwise CMake
                # defaults to Debug for try_compile/try_run, and the
                # test exes fail to start because we haven't shipped a
                # debug CRT (HAVE_C99_VSNPRINTF -> 0xc0000135).
                '-DCMAKE_TRY_COMPILE_CONFIGURATION=Release',
                "-DCMAKE_INSTALL_PREFIX=$wsInstallDir",
                "-DWIRESHARK_BASE_DIR=$wsCacheParent",
                '-DDISABLE_WERROR=ON',
                '-DBUILD_wireshark=OFF',
                '-DBUILD_tshark=OFF',
                '-DBUILD_logwolf=OFF',
                '-DBUILD_rawshark=OFF',
                '-DBUILD_dumpcap=OFF',
                '-DBUILD_text2pcap=OFF',
                '-DBUILD_mergecap=OFF',
                '-DBUILD_reordercap=OFF',
                '-DBUILD_editcap=OFF',
                '-DBUILD_capinfos=OFF',
                '-DBUILD_captype=OFF',
                '-DBUILD_randpkt=OFF',
                '-DBUILD_dftest=OFF',
                '-DBUILD_sharkd=OFF',
                '-DBUILD_androiddump=OFF',
                '-DBUILD_sshdump=OFF',
                '-DBUILD_ciscodump=OFF',
                '-DBUILD_udpdump=OFF',
                '-DBUILD_wifidump=OFF',
                '-DBUILD_dpauxmon=OFF',
                '-DBUILD_randpktdump=OFF',
                '-DBUILD_etwdump=OFF',
                $wsSrcDir
            )
            & cmake @args
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } else {
            Write-Host "reusing CMake cache in $wsBuildDir"
        }

        # Build the full default target (constrained by our BUILD_*=OFF
        # flags, this is libwsutil + libwiretap + libwireshark + libepan
        # and a handful of small support targets). Building only `epan`
        # leaves wireshark.lib unbuilt, and `cmake --install` then writes
        # WiresharkTargets.cmake referencing a missing import library.
        Write-Host "building Wireshark libs (Ninja)"
        & cmake --build .
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        Write-Host "installing dev tree to $wsInstallDir"
        & cmake --install .
        & cmake --install . --component Development
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    if (-not (Test-Path $wsConfigCmake)) {
        Write-Error "WiresharkConfig.cmake not produced under $wsInstallDir."
        exit 1
    }
}

# ----------------------------------------------------------------------
# Phase 3: build iccp.dll
# ----------------------------------------------------------------------
Write-Phase "Phase 3: build iccp.dll"

if (Test-Path $pluginBuild) {
    # Always start clean -- the plugin builds in seconds, and a stale
    # cache from a previous toolchain (e.g. VS generator) would refuse
    # to reconfigure for Ninja.
    Remove-Item -Recurse -Force $pluginBuild
}
New-Item -ItemType Directory -Path $pluginBuild -Force | Out-Null

Push-Location $pluginBuild
try {
    & cmake -G Ninja `
        -DCMAKE_BUILD_TYPE=RelWithDebInfo `
        -DCMAKE_TRY_COMPILE_CONFIGURATION=Release `
        "-DWireshark_DIR=$wsInstallDir\cmake" `
        $repoRoot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & cmake --build .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$dll = Join-Path $pluginBuild 'iccp.dll'
if (-not (Test-Path $dll)) {
    Write-Error "iccp.dll not produced at $dll"
    exit 1
}
$len = (Get-Item $dll).Length
Write-Host "produced $dll ($len bytes)"

# ----------------------------------------------------------------------
# Install to %APPDATA%\Wireshark\plugins\<X.Y>\epan
# ----------------------------------------------------------------------
if ($SkipInstall) {
    Write-Host "(-SkipInstall) leaving plugin at $dll"
} else {
    if (-not $PluginVersion) {
        # Derive X.Y from WiresharkConfigVersion.cmake so the plugin
        # lands in the dir the matching Wireshark runtime scans.
        $cfgVer = Join-Path $wsInstallDir 'cmake\WiresharkConfigVersion.cmake'
        $verLine = (Get-Content $cfgVer -ErrorAction SilentlyContinue |
                    Select-String 'PACKAGE_VERSION\s+"\d+\.\d+').Matches.Value
        if ($verLine -match '"(\d+\.\d+)') {
            $PluginVersion = $Matches[1]
        } else {
            Write-Warning "could not infer Wireshark minor from $cfgVer; defaulting to 4.2"
            $PluginVersion = '4.2'
        }
    }
    $userPluginDir = Join-Path $env:APPDATA "Wireshark\plugins\$PluginVersion\epan"
    New-Item -ItemType Directory -Path $userPluginDir -Force | Out-Null
    Copy-Item $dll -Destination $userPluginDir -Force
    Write-Host "installed to $userPluginDir\iccp.dll"
}

# Restore original env so a dot-sourced caller doesn't inherit our PATH/INCLUDE/LIB.
$env:PATH    = $origPath
$env:INCLUDE = $origInclude
$env:LIB     = $origLib

Write-Host ""
Write-Host "done." -ForegroundColor Green
