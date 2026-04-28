# win-build-env.ps1
#
# Set up a PowerShell session for building Wireshark 4.2 and the ICCP plugin
# on Windows. Dot-source this file to apply the environment changes to the
# current session:
#
#   . .\scripts\win-build-env.ps1
#
# After that, `cmake`, `perl`, `python`, `win_flex`, `win_bison`, `ninja`
# are all on PATH. MSVC is NOT applied here -- that needs a cmd subshell
# via vcvarsall.bat for sub-commands that need cl.exe directly. The
# Visual Studio CMake generator handles MSVC discovery automatically.

# Resolve from environment so each user sets their own paths. Set
# WIRESHARK_SRC / WIRESHARK_BUILD / WIRESHARK_VCVARS in your shell or via
# a profile script before dot-sourcing this file.
$wsSrc   = if ($env:WIRESHARK_SRC)    { $env:WIRESHARK_SRC }    else { '' }
$wsBuild = if ($env:WIRESHARK_BUILD)  { $env:WIRESHARK_BUILD }  else { '' }
$vcvars  = if ($env:WIRESHARK_VCVARS) { $env:WIRESHARK_VCVARS } else { '' }

# Merge machine + user PATH (captures everything installed persistently)
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$userPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path    = "$machinePath;$userPath"

# Add tools that Wireshark's build expects but aren't on default PATH.
# Python paths use $env:LOCALAPPDATA so they resolve per-user.
$extra = @(
    'C:\Program Files\CMake\bin',
    'C:\Strawberry\perl\bin',
    'C:\Strawberry\c\bin',
    "$env:LOCALAPPDATA\Programs\Python\Python312",
    "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\WinFlexBison.win_flex_bison_Microsoft.Winget.Source_8wekyb3d8bbwe"
)
foreach ($p in $extra) {
    if ((Test-Path $p) -and ($env:Path -notlike "*$p*")) {
        $env:Path = "$p;$env:Path"
    }
}

$env:WIRESHARK_SRC    = $wsSrc
$env:WIRESHARK_BUILD  = $wsBuild
$env:WIRESHARK_VCVARS = $vcvars

Write-Host "Wireshark source: $env:WIRESHARK_SRC"
Write-Host "Wireshark build:  $env:WIRESHARK_BUILD"
Write-Host "vcvarsall.bat:    $env:WIRESHARK_VCVARS"
Write-Host ""
Write-Host "Tool probe:"
foreach ($t in 'cmake','perl','python','win_flex','win_bison','ninja','git','cl') {
    $c = Get-Command "$t.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $src = $c.Source } else { $src = '(not on PATH -- may need vcvars for cl.exe)' }
    Write-Host ("  {0,-10} {1}" -f $t, $src)
}
