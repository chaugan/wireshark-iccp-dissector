# ICCP / TASE.2 Wireshark dissector plugin

A Wireshark dissector plugin for the **Inter-Control Center Communications
Protocol** (ICCP, IEC 60870-6 / TASE.2) — the application protocol
electric utility control centers use to exchange real-time data, events,
and device commands over MMS.

Out-of-tree C plugin, builds as a `.so` for Linux Wireshark or a `.dll`
for Windows Wireshark. Runs as a **post-dissector** on top of Wireshark's
existing MMS stack (TPKT → COTP → ISO 8327 Session → ISO 8823 Presentation
→ ACSE → MMS); it does not re-parse MMS but adds a semantic layer on top.

## What it does

- Marks ICCP associations in the Protocol column (`ICCP`)
- Tracks each association's state: `Candidate (Initiate seen) → Confirmed ICCP`
- Classifies every matched MMS object name against TASE.2 reserved
  names and maps to one of the nine IEC 60870-6-503 Conformance Blocks
- Labels each MMS operation in ICCP terms: `Associate-Request`,
  `Read-Request`, `Read-Response`, `Write-Request`, `InformationReport`,
  `DefineNamedVariableList-Request`, …
- For Block 5 Device Control, tracks per-device state
  (Idle → Selected → Operated) across the association and raises
  expert-info on anomalies: Operate without prior Select (SBO
  violation, Error severity), Direct Operate on a device (Warning)
- Never false-positives plain IEC 61850 MMS traffic as ICCP —
  associations that never see a TASE.2 reserved name stay in
  `Candidate` state and are not promoted

## Features at a glance

A condensed list of what plain MMS gives you vs what this plugin adds
on top. The plugin enriches MMS — it does not replace it — so all
MMS-level dissection still works underneath.

| Area                          | Plain MMS shows                  | This plugin adds                                                                            |
|-------------------------------|----------------------------------|---------------------------------------------------------------------------------------------|
| **Protocol identification**   | `MMS` or `MMS/IEC61850`          | `ICCP` Protocol column, `iccp` display filter, association state machine                    |
| **Naming conventions**        | raw `domainId.itemId` strings    | TASE.2 category (Bilateral Table, DSConditions, Device, Information_Message, …) + CB number |
| **Name scope**                | `domain-specific` vs `vmd-specific` enum | `iccp.scope` field: `VCC` (public) vs `Bilateral` (peer-pair / Bilateral Table id)          |
| **Association tracking**      | per-MMS-PDU only                 | per-conversation `Candidate → Confirmed → Closed` state across the whole flow              |
| **Block 5 Device Control**    | raw `Device_*Select / Operate` writes | cross-conversation SBO state machine (Idle → Selected → Operated) with timeout enforcement  |
| **SBO security**              | nothing                          | Expert-info on SBO violation (Operate without Select), Direct Operate, stale Select         |
| **Floating-point values**     | `0800000000` (raw 5-byte hex)    | Inline IEEE-754 decode rendered next to the raw bytes (`Decoded float: 49.978`)             |
| **Quality bytes**             | `bit-string: 80` (raw)           | Decoded TASE.2 IndicationPoint quality: Validity / Normal / TS_invalid / Source flags + summary |
| **IndicationPoints**          | structure of (float, bit-string) | Synthesised `Point #N: <value> [VALID / CURRENT / NORMAL / TS_OK]` row per point            |
| **Transfer Set reports**      | `success / failure` per item     | `iccp.report.*`: per-PDU points / success / failure / structured summary                    |
| **Operation column**          | `unconfirmed-PDU informationReport` | `ICCP InformationReport`, `ICCP Read-Request [Bilateral Table: <name>]`, …                  |
| **Statistics → ICCP**         | none                             | Operation, Object category, Conformance Block, Association state, Device sub-operation, Report outcomes, Points per Transfer Set, Point quality, Point value range, ICCP peers (src→dst), Operations by scope |
| **External tap**              | none                             | `register_tap("iccp")` exposing per-packet ICCP attributes for Lua / custom listeners        |
| **Display filters**           | `mms.*`                          | `iccp`, `iccp.point.value` (FT_FLOAT, graphable), `iccp.quality.validity`, `iccp.scope`, `iccp.domain`, `iccp.cb`, `iccp.device.state`, `iccp.object.category`, `iccp.report.*` |
| **I/O graphs**                | not meaningful for MMS           | `AVG(iccp.point.value)` plots grid frequency / MW / setpoints directly from a capture       |
| **PCAP scrubbing**            | not provided                     | `scripts/wash-pcap.py` SHA-256-hashes BER strings (and optionally numeric values) so a real utility capture can be shared without leaking site data |

### Conformance-Block coverage

| Block | Topic                                | This plugin |
|-------|--------------------------------------|-------------|
| 1     | Bilateral Table / version            | Recognised, Bilateral domain surfaced |
| 2     | DSConditions / Transfer Sets         | Recognised, point synthesis + per-set stats |
| 3     | Information Messages                 | Recognised by name pattern |
| 4     | Program Control                      | Recognised by name pattern |
| 5     | Device Control                       | Full SBO state machine + expert info |
| 6     | Event Conditions                     | Recognised by name pattern |
| 7     | Account tracking                     | Recognised by name pattern |
| 8     | Time Series                          | Recognised by name pattern |
| 9     | Additional / extended quality        | Recognised by name pattern |

Phases 4-9 deeper decode (typed-data parsing per block) is on the roadmap; current Phase 1-3 deliverables cover the blocks utility operators run in production.

## Display filter fields

| Filter                      | Type    | Description                                         |
|-----------------------------|---------|-----------------------------------------------------|
| `iccp`                      | —       | any ICCP-tagged packet                              |
| `iccp.association.state`    | string  | `Candidate (Initiate seen)` or `Confirmed ICCP`     |
| `iccp.operation`            | string  | `Associate-Request`, `Read-Request`, …              |
| `iccp.object.name`          | string  | MMS identifier that matched an ICCP name pattern    |
| `iccp.object.category`      | string  | `Bilateral Table`, `Device SBO Operate`, …          |
| `iccp.cb`                   | uint8   | Conformance Block number (1..9)                     |
| `iccp.device.state`         | string  | `Idle` / `Selected` / `Operated`                    |
| `iccp.scope`                | string  | `VCC` (public) or `Bilateral` (peer-pair scope)     |
| `iccp.domain`               | string  | Bilateral Table id when scope=Bilateral             |
| `iccp.point`                | string  | Synthesised `Point #N: <value> [quality]` row       |
| `iccp.point.value`          | float   | Decoded numeric point value (graphable in I/O)      |
| `iccp.point.quality`        | string  | Per-point quality summary                           |
| `iccp.quality.validity`     | uint8   | 0=VALID, 1=HELD, 2=SUSPECT, 3=NOT_VALID             |
| `iccp.quality.normal`       | bool    | Off-normal flag                                     |
| `iccp.quality.ts_invalid`   | bool    | Timestamp invalid flag                              |
| `iccp.quality.source`       | uint8   | 0=CURRENT, 1=HELD, 2=SUBSTITUTED, 3=GARBLED         |
| `iccp.value.real`           | float   | Inline-decoded MMS floating-point primitive         |
| `iccp.report.points`        | uint32  | Total AccessResult items in an InformationReport    |
| `iccp.report.success`       | uint32  | Successful items                                    |
| `iccp.report.failure`       | uint32  | Failed items                                        |

Expert-info filters:

| Filter                                                 | Severity     |
|--------------------------------------------------------|--------------|
| `_ws.expert.message contains "SBO violation"`          | Error        |
| `_ws.expert.message contains "physical device action"` | Warning      |
| `_ws.expert.message contains "stale_select"`           | Warning      |
| `_ws.expert.message contains "association handshake"`  | Note         |
| `_ws.expert.message contains "reserved object name"`   | Chat         |

## Supported Wireshark versions

Built and tested against **Wireshark 4.2** (Ubuntu 24.04 `libwireshark-dev`
and Windows-native MSVC build from source). Plugin code guards the
4.4+-only `plugin_describe()` symbol with `#if __has_include(<wsutil/plugins.h>)`,
so the same source tree should build cleanly against 4.4, 4.6, or master
too — you just rebuild per version.

Plugins are **ABI-locked** to the Wireshark minor version they were built
against (the `plugin_want_major` / `plugin_want_minor` symbols enforce
this at load time). A 4.2-built `iccp.so` will not load into 4.4; a
4.6-built `iccp.dll` will not load into 4.2.

### Targeting a different Wireshark release

**Linux (WSL / native)**: the Ubuntu package `libwireshark-dev` tracks the
distro's Wireshark version. To target a specific release, either upgrade
the distro (and thus its Wireshark) or build Wireshark from source and
point the plugin's CMake at that tree:

```bash
git clone --depth 1 --branch release-4.6 https://github.com/wireshark/wireshark.git ~/src/wireshark
cd ~/src/wireshark
mkdir build && cd build
cmake .. -DBUILD_wireshark=OFF
cmake --build . -j"$(nproc)"
sudo cmake --install . --prefix /usr/local
sudo cmake --install . --prefix /usr/local --component Development
# now rebuild our plugin against /usr/local
cd ~/build/wireshark_iccp
cmake /path/to/wireshark_iccp -DCMAKE_PREFIX_PATH=/usr/local
cmake --build .
```

**Windows**: our build scripts accept a `-Branch` parameter to
`win-build-wireshark.ps1`. For a 4.6 build:

```powershell
.\scripts\win-build-wireshark.ps1 `
    -Branch release-4.6 `
    -SourceDir  C:\dev\wireshark-4.6 `
    -BuildDir   C:\dev\wsbuild64-4.6 `
    -InstallDir C:\dev\ws-install-4.6 `
    -LibsDir    C:\Development\wireshark-x64-libs-4.6

.\scripts\win-build-plugin.ps1 -WiresharkInstall C:\dev\ws-install-4.6
```

Note: keep separate directories per version (source, build, install,
libs) so you can keep multiple versions around without clobbering.
Installing the resulting `iccp.dll` into `%APPDATA%\Wireshark\plugins\4.6\epan\`
then loads correctly in a 4.6 runtime.

## Build (Linux)

```bash
sudo apt install libwireshark-dev libwiretap-dev libwsutil-dev \
                 wireshark tshark build-essential cmake
mkdir -p ~/build/wireshark_iccp && cd ~/build/wireshark_iccp
cmake /path/to/wireshark_iccp
cmake --build . -j"$(nproc)"
# installs to Wireshark's user plugin dir reported in its CMake config:
cmake --build . --target copy_plugin
```

Alternatively copy `iccp.so` manually to
`~/.local/lib/wireshark/plugins/<major.minor>/epan/`.

## Build (Windows, via WSL) — development loop used for this repo

```bash
wsl -d ubuntu -- bash /mnt/c/.../wireshark_iccp/scripts/wsl-build.sh
wsl -d ubuntu -- bash /mnt/c/.../wireshark_iccp/scripts/wsl-verify.sh
```

`scripts/wsl-build.sh` configures + builds and puts `iccp.so` under
`~/build/wireshark_iccp/`. `wsl-verify.sh` copies it into the WSL
Wireshark plugin directory and sanity-checks `tshark -G plugins`.

The resulting `.so` runs only inside WSL's Linux Wireshark. A Windows
`.dll` targeting Windows-native Wireshark requires an MSVC toolchain
build against a Wireshark source tree matching the installed Windows
Wireshark version — cross-compiling from WSL to a Windows MSVC-
compatible DLL is not a clean path.

## Build (Windows, native MSVC)

Two scripts automate the full path. Assumes you have already installed:

- Visual Studio 2022 Build Tools **with the "Desktop development with C++" workload**
  (this is not the default — add it via the VS Installer's Modify → workloads)
- CMake, Strawberry Perl, winflexbison, Python 3, Git

Then from a PowerShell prompt in the repo root:

```powershell
# One-time (~5 min): clone Wireshark 4.2 source, download prebuilt deps,
# build libwireshark/libwsutil/libwiretap, install headers+libs+cmake config.
.\scripts\win-build-wireshark.ps1

# Every time you change plugin source (~30 sec): build iccp.dll and
# install to %APPDATA%\Wireshark\plugins\4.2\epan\
.\scripts\win-build-plugin.ps1
```

### Optional: full GUI build

Default `win-build-wireshark.ps1` is libs-only (no Qt, ~3 min build).
If you have Qt6 under `C:\Qt\<version>\msvc*_64\` pass `-WithGui` and
the script auto-discovers it and builds the full Wireshark GUI
(`Wireshark.exe`) along with the libs and CLI tools. Takes ~10 min
instead of 3 but leaves a self-contained `run\RelWithDebInfo\Wireshark.exe`
you can launch directly:

```powershell
.\scripts\win-build-wireshark.ps1 -WithGui
# or force a specific Qt:
.\scripts\win-build-wireshark.ps1 -WithGui -Qt6Dir C:\Qt\6.7.2\msvc2019_64
```

Install Qt6 via https://www.qt.io/download-qt-installer (select any
"MSVC ... 64-bit" build — msvc2019_64 works fine with MSVC 2022). The
`Qt Core 5 Compatibility`, `Qt Multimedia`, `Qt 5 Compatibility Module`
modules are needed.

Defaults:

| Path | Contents |
|------|----------|
| `C:\dev\wireshark\` | Wireshark 4.2 source (shallow clone) |
| `C:\dev\wsbuild64\` | Wireshark build tree (contains `run\RelWithDebInfo\tshark.exe`) |
| `C:\dev\ws-install\` | Wireshark install tree (headers, libs, `WiresharkConfig.cmake`) |
| `C:\Development\wireshark-x64-libs-4.2\` | Prebuilt Windows deps (glib, gnutls, …) from Wireshark's dev-libs site |
| `C:\dev\iccp-build\RelWithDebInfo\iccp.dll` | The plugin DLL |
| `%APPDATA%\Wireshark\plugins\4.2\epan\iccp.dll` | Installed location |

Override any of these via parameters, e.g.
`.\scripts\win-build-wireshark.ps1 -SourceDir D:\ws\src -InstallDir D:\ws\install`.

### Quick verification

The Wireshark source build produces a local `tshark.exe` at
`C:\dev\wsbuild64\run\RelWithDebInfo\tshark.exe` (version 4.2.15). The
plugin is ABI-locked to that version, so you can sanity-check without
installing a separate Wireshark runtime:

```powershell
$tshark = 'C:\dev\wsbuild64\run\RelWithDebInfo\tshark.exe'
$pcap   = '.\pcaps\generated\iccp-phase1.pcap'
& $tshark -G plugins | Select-String iccp
& $tshark -r $pcap -d tcp.port==10102,tpkt -Y iccp | Select-Object -First 10
```

### Runtime coexistence with stock Wireshark

A plugin built against Wireshark 4.2 **does not load** into Wireshark 4.6
or any other minor version — the ABI is pinned via the `plugin_want_major`
/ `plugin_want_minor` symbols. Options:

- Use the `tshark.exe` from our own `C:\dev\wsbuild64\run\RelWithDebInfo\`
  build tree (this *is* Wireshark 4.2.15 runtime, GUI-less).
- Install a stock Wireshark 4.2.x installer from wireshark.org/download
  side-by-side with any other version, then copy `iccp.dll` into its
  `%APPDATA%\Wireshark\plugins\4.2\epan\`.
- Build for a different Wireshark minor version by re-running
  `win-build-wireshark.ps1 -Branch release-4.4` (etc.).

## Generating a test PCAP

No public ICCP PCAPs of meaningful quality are known (utilities guard
them as sensitive). This tree ships a generator that uses
`libIEC61850`'s MMS server + `mms_utility` client on localhost,
requesting TASE.2-reserved variable names. The server returns
"does-not-exist" but the request PDU on the wire carries the ICCP
name, which is enough to exercise the dissector.

```bash
# requires libiec61850 built once under ~/src/libiec61850
bash scripts/gen-pcap.sh
```

Produces `pcaps/generated/iccp-phase1.pcap` (~280 packets covering all
9 conformance blocks, Device Control state-machine, and an SBO violation).

## Running the regression suite

```bash
bash tests/regression.sh
```

25 assertions covering all 9 conformance blocks, all tracked operations,
the Device-Control state machine, and the no-false-positive guard
(plain-MMS Initiate doesn't promote to Confirmed ICCP).

## Sanitizing a real-world ICCP capture for sharing

Real ICCP traffic usually contains control-center IPs, substation
codes, breaker designations and operator usernames embedded in MMS
VisibleString identifiers — information that's sensitive to share.
`scripts/wash-pcap.py` rewrites the capture in place with
length-preserving substitutions so the ASN.1 stays well-formed and
the washed capture still dissects end-to-end.

### What it rewrites

| Field | Becomes |
|-------|---------|
| IPv4 addresses | `192.0.2.x` (RFC 5737 documentation range, consistent mapping) |
| MAC addresses | `00:00:5E:00:53:xx` (IEEE documentation OUI, consistent mapping) |
| MMS VisibleString identifiers (variable names, domain names, bilateral-table names) | `VAR_<hash>_____…` of identical length, deterministic by content |

Well-known ICCP names (`TASE2_Version`, `Supported_Features`,
`Bilateral_Table_ID`) are kept verbatim so the washed trace still
reads as ICCP. Pass `--preserve-extra <name>` to whitelist additional
strings.

### What it does **not** change

- TPKT / COTP / ISO Session / Presentation / ACSE framing
- ASN.1 tags, CHOICE selectors, length fields
- Presentation Context Identifier (so MMS still dispatches after washing)
- Typed-data primitive values (floats, ints, bit-strings, binary-times) — these often carry operational state; keep or redact separately as appropriate.

### Usage

The script is pure Python 3 with no dependencies, legacy-pcap input only (pcapng needs a one-step `editcap -F pcap` first).

```powershell
# Windows
editcap -F pcap real-capture.pcapng real-capture.pcap
python3 scripts\wash-pcap.py real-capture.pcap safe-to-share.pcap
```

```bash
# Linux / WSL
editcap -F pcap real-capture.pcapng real-capture.pcap
python3 scripts/wash-pcap.py real-capture.pcap safe-to-share.pcap
```

Smoke test: `bash tests/test-washer.sh` (validates on the bundled sample capture, 6 checks).

**Do review the washed file before publishing.** The script catches
the common cases but can miss vendor-specific extensions. If your
capture has proprietary ASN.1 structures with non-VisibleString
identifiers, extend the scrubber manually.

## Code-signing the Windows DLL (optional)

Some corporate Wireshark installs refuse to load unsigned plugins.
`scripts/win-sign.ps1` wraps `signtool.exe` from the Windows SDK and
covers three cert sources:

```powershell
# (A) Dev self-signed -- good for local testing on your own machine
.\scripts\win-sign.ps1 -DevSelfSigned

# (B) A purchased cert already imported to Cert:\CurrentUser\My
.\scripts\win-sign.ps1 -CertThumbprint 1234567890ABCDEF...

# (C) A PFX file on disk
.\scripts\win-sign.ps1 -PfxFile my-codesign.pfx `
                       -PfxPassword (Read-Host -AsSecureString -Prompt 'pfx pw')
```

The script always adds an RFC 3161 timestamp (default
`http://timestamp.digicert.com`) so the signature stays valid after
the cert expires.

**Which cert to get:**

- **Self-signed** is fine for solo dev loop but every other machine
  will still show "publisher: unknown" unless the user imports the
  cert into Trusted Root Certification Authorities (which they
  shouldn't).
- **Sectigo / DigiCert / GlobalSign OV** code-signing certs are the
  usual commercial option — around USD 100-400 per year for standard,
  300-700 for EV. Purchase, verify identity, receive either a
  hardware token (EV) or a PFX (standard).
- **SignPath.Foundation** offers *free* code signing for
  qualifying open-source projects via a CI integration
  (<https://signpath.io/products/foundation>). Requires a GitHub
  project meeting their criteria; once accepted the signing happens
  server-side from the release CI pipeline.

## Using the plugin on a real-world ICCP capture

Real-world TASE.2 links associate once and then stay up for days or
weeks. If your capture started mid-session (very common) Wireshark
missed the Connect-Presentation (A-ASSOCIATE) exchange — the single
packet that binds each Presentation Context Identifier (PCI) to its
Abstract Syntax OID. Without that binding, Wireshark shows
*"dissector is not available"* under ISO 8823 Presentation on every
MMS frame, and our ICCP post-dissector never runs because its
`proto_is_frame_protocol(pinfo->layers, "mms")` gate is never TRUE.

Fix: tell Wireshark manually which PCI is MMS.

### Step 1 — find the PCI the session uses

**Linux / WSL**

```bash
tshark -r your.pcap -T fields -e pres.presentation_context_identifier \
    | awk 'NF' | sort -u
```

**Windows (PowerShell)**

```powershell
tshark -r .\your.pcap -T fields -e pres.presentation_context_identifier |
    Where-Object { $_ -match '\d' } | Sort-Object -Unique
```

Typical output is a single small integer like `3` (often `1` + `3` if
you also want to nail down ACSE: `1` is the ACSE context, `3` is the
MMS one — numbers vary per vendor).

### Step 2 — bind that PCI to MMS

**In the Wireshark GUI:**

Edit → Preferences → Protocols → **PRES** → **Users Context List** →
*Edit…* → *New*

| Field | Value |
|-------|-------|
| Context Id | the number from step 1 |
| Syntax Name OID | `1.0.9506.2.1` (MMS abstract-syntax, ISO 9506-2) |

If you saw two PCIs in step 1, add a second row with the ACSE OID
`2.2.1.0.1`. Click *OK* → *OK*. The preference persists in your
Wireshark profile.

**From the command line (same effect, scriptable):**

```bash
tshark -r your.pcap \
    -o 'pres.users_table:"3","1.0.9506.2.1"' \
    -Y iccp -V | less
```

### Step 3 — confirm MMS now dispatches

```bash
tshark -r your.pcap -o 'pres.users_table:"3","1.0.9506.2.1"' \
    -T fields -e frame.protocols | sort -u | grep mms
```

You should see `eth:ethertype:ip:tcp:cotp:ses:pres:mms` on data frames.
From that point our ICCP post-dissector fires and `iccp.operation`,
`iccp.object.category`, `iccp.cb`, etc. become valid display filters.

If MMS still doesn't dispatch, the peers may have negotiated a
vendor-specific abstract-syntax OID instead of the canonical
`1.0.9506.2.1`. Pull the OID directly from the (rare, lucky) frame
that carries the CP:

```bash
tshark -r your.pcap -T fields -e pres.abstract_syntax_name | sort -u
```

…and substitute that OID in step 2.

---

## Non-obvious implementation notes

Documented in `packet-iccp.c` comment header but worth surfacing:

1. Post-dissectors that inspect other protocols' fields **must** call
   `set_postdissector_wanted_hfids()` at handoff, or the tree optimizer
   elides those fields on first-pass dissection and the scans see
   nothing.
2. `proto_find_first_finfo()` in Wireshark 4.2 has persistent/stale
   behavior — it returns non-NULL on packets where the field is not
   present. Use `proto_all_finfos()` for bulletproof per-packet
   accuracy.
3. asn2wrs registers **duplicate hf ids** for the same abbrev when a
   CHOICE alternative appears at multiple use sites
   (e.g. `mms.read_element` has one hfid under
   `ConfirmedServiceRequest` and another under `ConfirmedServiceResponse`).
   `proto_registrar_get_id_byname()` returns only the first, which is
   a footgun. This plugin works around it by matching fields via
   `hfinfo->abbrev` during the tree walk and by enumerating all
   fields under the MMS protocol when marking them wanted.
4. In a domain-specific `ObjectName`, the variable name lives in
   `mms.itemId`, not in `mms.Identifier`. The latter is a named-type
   base rarely populated in practice.
5. ICCP uses TCP port 102. On non-standard ports, Wireshark won't
   dispatch TPKT / COTP / MMS automatically — pass
   `-d tcp.port==<port>,tpkt` to force it.

## License

GPL-2.0-or-later (SPDX: `GPL-2.0-or-later`), matching Wireshark's
own license.
