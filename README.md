# ICCP / TASE.2 Wireshark dissector plugin

A Wireshark dissector plugin for the **Inter-Control Center Communications
Protocol** (ICCP, IEC 60870-6 / TASE.2) — the application protocol
electric utility control centers use to exchange real-time data, events,
and device commands over MMS.

Out-of-tree C plugin, builds as a `.so` for Linux Wireshark or a `.dll`
for Windows Wireshark. Wraps the MMS dissector at OID dispatch — sits
under the existing TPKT → COTP → ISO 8327 Session → ISO 8823 Presentation
→ MMS chain and adds a semantic layer on top without re-parsing MMS.

**Pre-built binaries** for Wireshark 4.2 / 4.4 / 4.6 (Linux `.so` and
Windows `.dll`) are published on the [Releases page](https://github.com/chaugan/wireshark-iccp-dissector/releases).
Each binary is ABI-locked to its target Wireshark minor — `iccp.so`
built against 4.2 will not load into 4.4. Drop into
`~/.local/lib/wireshark/plugins/<X.Y>/epan/iccp.so` (Linux) or
`%APPDATA%\Wireshark\plugins\<X.Y>\epan\iccp.dll` (Windows).

## Where things work — tshark vs Wireshark GUI

| Capability                                                | tshark CLI                  | Wireshark GUI                                                          |
|-----------------------------------------------------------|-----------------------------|------------------------------------------------------------------------|
| ICCP tree under the MMS tree (Operation, CB, scope, …)    | yes                         | yes                                                                    |
| Synthesised `Point #N: <value> [quality]` rows            | yes                         | yes                                                                    |
| Inline IEEE-754 float decode under `mms.floating_point`   | yes                         | yes                                                                    |
| TASE.2 quality byte → named flag subfields                | yes                         | yes                                                                    |
| Display filters (`iccp`, `iccp.point.value`, `iccp.scope`, …) | yes                     | yes (first-pass; the OID-level wrapper runs during dissection, so `iccp.*` fields materialise without a `Ctrl+R`) |
| Protocol column reads `ICCP`                              | yes                         | yes (since v0.4 the plugin wraps MMS at OID dispatch instead of post-dissecting, so `COL_PROTOCOL` is `ICCP` during the first pass) |
| Info column reads `ICCP InformationReport [<category>: <name>]` | yes                  | yes (same OID wrapper path as Protocol column)                          |
| `Statistics → ICCP/Statistics` populates                  | yes (`-z iccp,tree`)        | yes — an always-on tap listener fires on every dissection and re-emits saved tap data on retap, so the dialog populates immediately on first open |
| Per-point recovery past the upstream MMS recursion bug    | yes                         | yes — full listing under the iccp tree, with each Point #N as a structured subtree (Index / Slot / Value / Quality / Name); see *Non-obvious implementation notes*. The underlying upstream MMS bug is fixed in Wireshark 4.2.3+, so on 4.2.3 / 4.4 / 4.6 the listing is "Per-point listing" (parallel view); on 4.2.0–4.2.2 it's "Recovered points" (truncated MMS subtree workaround). The plugin detects per-frame which mode applies. |
| Variable-name mapping (slot → operator name)              | yes (UAT preference)        | yes — Edit → Preferences → Protocols → ICCP → DSD Mapping. One row per `(domain, transferSet, slot, name)`; populated from the bilateral table doc. Names appear as `iccp.point.name` and inline in each Point #N row |
| Expert-info on SBO violations                             | yes (synthetic capture)     | yes (synthetic capture)                                                |

Both interfaces give the same functional analysis (tree, filters, stats,
expert info, per-point quality + values, slot-to-name mapping). Version
history of the friction points cleared away:

- **v0.4** — wraps MMS at OID dispatch instead of post-dissecting, so the
  GUI's Protocol / Info columns read `ICCP` / `ICCP <op>` during the
  first-pass packet-list render (no more `Ctrl+R` for the columns).
- **v0.5** — always-on `frame` tap listener with `TL_REQUIRES_PROTO_TREE`
  + first-pass tap_info save/replay, so `Statistics → ICCP/Statistics`
  populates immediately on first open.
- **v0.5.1** — `TRY/CATCH(DissectorError)` around the MMS call + a
  hand-rolled BER walker recover the per-point values past the upstream
  `mms.c:2103` recursion-depth assertion that aborts MMS dissection
  after ~2 items in any `SEQUENCE OF Data`.
- **v0.6** — structured Point #N subtree under the iccp tree (each
  point has Index / Slot / Value / Quality children); `iccp.point.slot`
  matches the listOfAccessResult position used in bilateral table
  documentation; `iccp.point.value` and `iccp.value.real` promoted to
  `FT_DOUBLE` so right-click `field == <displayed>` filters match
  without single-precision rounding mismatch; new DSD-mapping UAT
  preference adds operator-supplied variable names per slot;
  Recovered-points header text auto-adapts to "Per-point listing" on
  Wireshark 4.2.3+ where the MMS subtree above is no longer truncated.
- **v0.6.1** — Wireshark 4.6 compatibility + DSD auto-discovery.
  `walk_tree` now also matches `mms.objectName_domain_specific_itemId`
  (the asn2wrs-renamed `itemId` in 4.6) and `mms.aa_specific`, so the
  per-Transfer-Set / per-Conformance-Block stats axes populate with
  named buckets again on 4.6 (4.2 / 4.4 unaffected — the abbrev
  `mms.itemId` is still recognised). Op classification is now also
  derived from the PDU's BER tags directly, so the GUI's two-pass
  display-filter mode (`iccp`, `iccp.operation`, `iccp.point.name == …`)
  matches every frame instead of one. New auto-discovery path:
  `DefineNamedVariableList-Request` PDUs are walked at dissection
  time, the ordered (listDomain, listName) → variable-list mapping
  is cached per file, and `iccp.point.name` auto-populates on
  subsequent reports referring to that data set — UAT entries are
  no longer required when the negotiation is in the capture (and
  remain the fallback when it isn't). `gen-iccp-pcap.py` emits the
  matching DefineNVL exchange so the synthetic pcap exercises this
  path end-to-end without manual setup.

## What it does (functional behaviour, valid in both tshark and GUI)

- Recognises ICCP associations and tracks each association's lifecycle
  (`Candidate (Initiate seen) → Confirmed ICCP → Closed`) across the
  whole conversation, not just per-PDU
- Classifies every matched MMS object name against TASE.2 reserved
  names and maps to one of the nine IEC 60870-6-503 Conformance Blocks
- Labels each MMS operation in ICCP terms: `Associate-Request`,
  `Read-Request`, `Read-Response`, `Write-Request`, `InformationReport`,
  `DefineNamedVariableList-Request`, … (visible in the iccp tree, and
  in tshark's Info column)
- Distinguishes name scope: `VCC` (VMD-global, public inside the
  control center) vs `Bilateral` (scoped to a Bilateral Table /
  peer-pair); surfaces the Bilateral Table domain id when present
- For Block 5 Device Control, tracks per-device state
  (`Idle → Selected → Operated`) across the association and raises
  expert-info on anomalies: Operate without prior Select (SBO
  violation, Error severity), Direct Operate on a device (Warning).
  *Tested on the synthetic capture from `scripts/gen-pcap.sh`; we have
  no real-world Block-5 traffic to validate against.*
- Synthesises per-point rows for TASE.2 IndicationPoints: a structure
  of `(floating-point, bit-string)` becomes
  `Point #N: 49.998 [VALID / CURRENT / NORMAL / TS_OK]` on a single
  line under the MMS tree
- Decodes the TASE.2 quality byte into named filterable subfields
  (`iccp.quality.validity / .normal / .ts_invalid / .source`)
- Decodes `mms.floating_point` bytes inline as IEEE-754 (so
  `0800000000` shows `Decoded float: 0.0` next to the raw hex)
- Never false-positives plain IEC 61850 MMS traffic as ICCP —
  associations that never see a TASE.2 reserved name stay in
  `Candidate` state and are not promoted

## Features at a glance

What plain MMS gives you vs what this plugin adds. The "plain MMS"
column is what you'd see with the built-in Wireshark MMS dissector
(`epan/dissectors/packet-mms.c`) and no plugin loaded; verified by
inspection against Wireshark 4.6 and by running tshark with this
plugin removed. Behaviour is the same in tshark and the Wireshark GUI
on first open — no `Ctrl+R` dance.

| Area                          | Plain MMS shows                  | This plugin adds                                                                            |
|-------------------------------|----------------------------------|---------------------------------------------------------------------------------------------|
| **ICCP subtree**              | nothing                          | An `[Inter-Control Center Communications Protocol (ICCP/TASE.2)]` block under MMS with operation, association state, conformance block, scope, domain, point summaries, report counts |
| **Naming conventions**        | raw `domainId` / `itemId` strings under `domain-specific` ObjectName | TASE.2 category (Bilateral Table, DSConditions, Device, Information_Message, …) + Conformance Block number |
| **Name scope**                | the `domain-specific` / `vmd-specific` / `aa-specific` ObjectName CHOICE alternative | `iccp.scope` field: `VCC` (public) vs `Bilateral` (peer-pair); the Bilateral Table domain id is surfaced as a top-level field rather than buried inside the ObjectName |
| **Association tracking**      | per-PDU only — MMS tracks request/response invokeIDs but has no notion of an ICCP association lifecycle | per-conversation `Candidate → Confirmed → Closed` state across the whole TCP flow, promoted only when a TASE.2 reserved name has actually been seen (so plain IEC 61850 traffic doesn't false-positive) |
| **Block 5 Device Control**    | raw `Device_*Select / Operate` Read/Write PDUs, no semantics | cross-conversation SBO state machine (Idle → Selected → Operated). Validated on synthetic capture only |
| **SBO security**              | nothing                          | Expert-info on SBO violation (Operate without Select), Direct Operate, stale Select. Synthetic only |
| **Floating-point values**     | `mms.floating_point` is **`FT_BYTES`** in MMS — the proto tree shows the raw 5-byte hex (e.g. `0800000000`); MMS only decodes the float internally for IEC-61850 Info-column text and never exposes a decoded value as a sub-field for ICCP traffic | Inline IEEE-754 decode emitted as a generated `iccp.value.real` (FT_DOUBLE since v0.6) child under each `mms.floating_point` leaf (`Decoded float: 49.97800064086914`); filter- and graph-able. Stored as double so right-click → *Apply as Filter* on a displayed value matches without single-precision rounding |
| **Quality bytes**             | `mms.data_bit-string` is **`FT_BYTES`** — quality byte shown as raw hex with no flag-level decode | Decoded TASE.2 IndicationPoint quality: `iccp.quality.validity / .off_normal / .timestamp_invalid / .source` (each filter-able) plus a one-line `iccp.quality.summary` digest |
| **IndicationPoints**          | generic `mms.structure_element` (FT_NONE) with separate float and bit-string children — no pairing | Synthesised `Point #N: <value> [VALIDITY / SOURCE / NORMAL / TS_OK]` single-line row per point under each structure |
| **Transfer Set reports**      | `AccessResult: success / failure` per item — no per-report summary | `iccp.report.*`: per-PDU `point_count`, `success_count`, `failure_count`, structured-flag, and a `floats=N bit-strings=N …` summary line |
| **Per-point recovery**        | bug-capped on Wireshark **4.2.0 / 4.2.1 / 4.2.2**: the MMS dissector hits a recursion-depth assertion at `mms.c:dissect_mms_Data` once a `SEQUENCE OF Data` has more than ~2 items, and aborts. On real ICCP captures this fires on essentially every report (which carry tens to hundreds of points), so plain MMS shows at most the first 1-2 items in the proto tree and pastes `[Dissector bug, … mms.c …]` into Info. **Fixed upstream in Wireshark 4.2.3** (the bad `recursion_depth - cycle_size` underflow in `dissect_mms_Data` / `dissect_mms_TypeSpecification` / `dissect_mms_AlternateAccess` / `dissect_mms_VariableSpecification` was changed to restore the captured baseline) | BER walker decodes `listOfAccessResult` / `listOfData` directly from the PDU bytes regardless of whether MMS truncated. On real-world captures this lifts max points/report from 1 to 384. Each recovered point gets a structured Point #N subtree with Index / Slot / Value / Quality / (optional) Name children, all filterable. Header text auto-adapts: "Recovered points: N — MMS truncated this frame" on 4.2.0–4.2.2, "Per-point listing: N (parallel view of MMS listOfAccessResult)" on 4.2.3+. `iccp_dispatch_via_oid` wraps the MMS call in `TRY/CATCH(DissectorError)` so the bug text no longer appears in `col_info` either |
| **Slot ↔ variable name**      | none — bilateral table position is implicit in the wire encoding (no per-point name on the wire); operators carry the slot-to-name mapping in their bilateral agreement out of band | `iccp.point.slot` exposes the 0-based listOfAccessResult position (matches what the bilateral table documents); a UAT preference (Edit → Preferences → Protocols → ICCP → DSD Mapping) maps `(domain, transferSet, slot)` rows to operator-supplied variable names that surface as `iccp.point.name` (filterable) and inline in each Point #N row text |
| **Protocol column**           | `MMS` (or `MMS/IEC61850` when the IEC 61850 mapping preference is on, which is the default) | `ICCP` in both tshark and the GUI — the OID wrapper since v0.4 owns the ICCP abstract-syntax OIDs and writes the column during first-pass dissection |
| **Info column**               | `col_clear` at start of `dissect_mms`; for ICCP-flavoured PDUs the MMS dissector then writes nothing (the `IEC 61850` Info-column branches all gate on IEC-61850-specific markers like `IEC61850_8_1_RPT`, `IEC61850_ITEM_ID_OPER`, the IEC-61850 confirmed-service PDU types). For an Initiate-Request MMS does write `Associate Request`; for InformationReports — the dominant ICCP traffic — Info is left empty and you typically see whatever PRES/SES wrote (`DATA TRANSFER (DT) SPDU`) | `<MMS PDU label> \| ICCP <op> [<category>: <name>]` in both tshark and the GUI; for Write-Request it also includes the inline-decoded float (e.g. `confirmed-RequestPDU -11.76 \| ICCP Write-Request`) |
| **Statistics tree axes**      | none — the MMS dissector does not register a `stats_tree` | Operation, Object category, Conformance Block, Association state, Device sub-operation, Report outcomes, Points per Transfer Set, Point quality, Point value range, ICCP peers (src→dst), Operations by scope |
| **External tap**              | none — the MMS dissector does not call `register_tap()` | `register_tap("iccp")` exposes per-packet ICCP attributes (op, cb, category, scope, domain, point counts, quality breakdown, value min/max/sum) to Lua / custom listeners |
| **Display filters**           | `mms.*` only; numeric filters on values don't work because `mms.floating_point` is FT_BYTES | `iccp`, `iccp.point.value` (FT_FLOAT, I/O-graphable), `iccp.quality.*`, `iccp.scope`, `iccp.domain`, `iccp.cb`, `iccp.device.state`, `iccp.object.category`, `iccp.report.*`, `iccp.value.real` |
| **I/O graphs**                | not numerically aggregable — `mms.floating_point` is FT_BYTES so `AVG()` / `MIN()` / `MAX()` can't operate on the value | `AVG(iccp.point.value)`, `MAX(iccp.point.value)`, etc. plot grid frequency / MW / setpoints from a capture           |
| **PCAP scrubbing**            | not provided                     | `scripts/wash-pcap.py` SHA-256-hashes BER strings; `--scrub-numeric` also redacts primitive numeric values (off by default — turning it on can break MMS dispatch on captures that key off specific values) |

### Conformance-Block coverage

| Block | Topic                                | This plugin                                                                                |
|-------|--------------------------------------|--------------------------------------------------------------------------------------------|
| 1     | Bilateral Table / version            | Names recognised; Bilateral scope + domain id surfaced                                     |
| 2     | DSConditions / Transfer Sets         | Names recognised; (float, bit-string) point synthesis; per-set stats                       |
| 3     | Information Messages                 | Names recognised by pattern; no payload-typed decode yet                                   |
| 4     | Program Control                      | Names recognised by pattern; no payload-typed decode yet                                   |
| 5     | Device Control                       | Full SBO state machine + expert info. Validated on synthetic capture; no real Block-5 PCAP |
| 6     | Event Conditions                     | Names recognised by pattern; no payload-typed decode yet                                   |
| 7     | Account tracking                     | Names recognised by pattern; no payload-typed decode yet                                   |
| 8     | Time Series                          | Names recognised by pattern; no payload-typed decode yet                                   |
| 9     | Additional / extended quality        | Names recognised by pattern; no payload-typed decode yet                                   |

Phases 4–9 deeper decode (typed-data parsing per block) is roadmap;
Phase 1–3 deliverables cover Blocks 1, 2, 5 — the ones utility
operators actually run in production.

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
| `iccp.note`                 | string  | Free-form annotation attached to PDUs of interest   |
| `iccp.point`                | string  | Synthesised `Point #N: <value> [quality]` row (filterable as a single string match) |
| `iccp.point.value`          | double  | Decoded numeric point value (FT_DOUBLE since v0.6 — right-click `== <displayed>` matches; graphable in I/O graphs via `AVG()` / `MAX()` / `MIN()`) |
| `iccp.point.quality`        | string  | Per-point quality summary (`VALID` / `HELD` / `SUSPECT` / `NOT_VALID`) |
| `iccp.point.index`          | uint32  | 1-based ordinal among the recovered float points in the report. Use `iccp.point.slot` to correlate with bilateral table docs — they're not the same when the report has non-point header items |
| `iccp.point.slot`           | uint32  | 0-based position in `listOfAccessResult`. Matches the partner's Data Set Definition slot; this is what bilateral table documentation uses |
| `iccp.point.name`           | string  | Operator-supplied variable name for this slot, when a row is present in the DSD-Mapping UAT preference (Edit → Preferences → Protocols → ICCP → DSD Mapping) |
| `iccp.quality`              | uint8   | Raw TASE.2 quality byte (bitmask parent)            |
| `iccp.quality.validity`     | uint8   | 0=VALID, 1=HELD, 2=SUSPECT, 3=NOT_VALID             |
| `iccp.quality.off_normal`   | bool    | Off-normal flag (bit 5)                             |
| `iccp.quality.timestamp_invalid` | bool | Timestamp invalid flag (bit 4)                     |
| `iccp.quality.source`       | uint8   | 0=CURRENT, 1=HELD, 2=SUBSTITUTED, 3=GARBLED         |
| `iccp.quality.summary`      | string  | One-line `VALIDITY / SOURCE / NORMAL / TS_OK` digest |
| `iccp.value.real`           | double  | Inline-decoded MMS floating-point primitive (FT_DOUBLE since v0.6) |
| `iccp.report.point_count`   | uint32  | Total AccessResult items in an InformationReport (recovered from PDU bytes, so accurate even past the upstream MMS recursion-depth bug) |
| `iccp.report.success_count` | uint32  | Successful items                                    |
| `iccp.report.failure_count` | uint32  | Failed items                                        |
| `iccp.report.structured`    | bool    | Whether the report payload contains TASE.2-shaped structures |
| `iccp.report.summary`       | string  | Per-PDU `floats=N bit-strings=N binary-times=N visible-strings=N octet-strings=N` digest |

Expert-info filters (each fires under specific ICCP conditions):

| Filter                                                       | Severity     | Fires on                                                |
|--------------------------------------------------------------|--------------|---------------------------------------------------------|
| `_ws.expert.message contains "SBO violation"`                | Error        | Device Operate without a preceding Select               |
| `_ws.expert.message contains "physical device action"`       | Warning      | Device Operate (any) — physical action requested        |
| `_ws.expert.message contains "long after Select"`            | Warning      | Operate after the Select-Before-Operate timeout window  |
| `_ws.expert.message contains "association handshake"`        | Note         | A-ASSOCIATE Initiate-Request / -Response observed       |
| `_ws.expert.message contains "InformationReport"`            | Note         | InformationReport on an ICCP association                |
| `_ws.expert.message contains "reserved object name"`         | Chat         | An MMS name matched a TASE.2 reserved pattern           |

## Supported Wireshark versions

Built and released for **Wireshark 4.2, 4.4 and 4.6** (Linux `.so` and
Windows `.dll` for each minor — see the [Releases page](https://github.com/chaugan/wireshark-iccp-dissector/releases)).
The same source tree builds against any of the three; plugin code
guards the 4.4+-only `plugin_describe()` symbol with
`#if __has_include(<wsutil/plugins.h>)` so you don't have to fork.

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
cd ~/build/wireshark-iccp-dissector
cmake /path/to/wireshark-iccp-dissector -DCMAKE_PREFIX_PATH=/usr/local
cmake --build .
```

**Windows**: our build scripts accept a `-Branch` parameter to
`win-build-wireshark.ps1`. Pass each path explicitly (or set the
`WIRESHARK_*` env vars described in the *Defaults* table below). For a
4.6 build:

```powershell
.\scripts\win-build-wireshark.ps1 `
    -Branch release-4.6 `
    -SourceDir  <wireshark-source-4.6> `
    -BuildDir   <wireshark-build-4.6> `
    -InstallDir <wireshark-install-4.6> `
    -LibsDir    <wireshark-libs-4.6>

.\scripts\win-build-plugin.ps1 -WiresharkInstall <wireshark-install-4.6>
```

Note: keep separate directories per version (source, build, install,
libs) so you can keep multiple versions around without clobbering.
Installing the resulting `iccp.dll` into `%APPDATA%\Wireshark\plugins\4.6\epan\`
then loads correctly in a 4.6 runtime.

## Build (Linux)

```bash
sudo apt install libwireshark-dev libwiretap-dev libwsutil-dev \
                 wireshark tshark build-essential cmake
mkdir -p ~/build/wireshark-iccp-dissector && cd ~/build/wireshark-iccp-dissector
cmake /path/to/wireshark-iccp-dissector
cmake --build . -j"$(nproc)"
# installs to Wireshark's user plugin dir reported in its CMake config:
cmake --build . --target copy_plugin
```

Alternatively copy `iccp.so` manually to
`~/.local/lib/wireshark/plugins/<major.minor>/epan/`.

## Build (Windows, via WSL) — development loop used for this repo

```bash
wsl -d ubuntu -- bash /path/to/wireshark-iccp-dissector/scripts/wsl-build.sh
wsl -d ubuntu -- bash /path/to/wireshark-iccp-dissector/scripts/wsl-verify.sh
```

`scripts/wsl-build.sh` configures + builds and puts `iccp.so` under
`~/build/wireshark-iccp-dissector/`. `wsl-verify.sh` copies it into the
WSL Wireshark plugin directory and sanity-checks `tshark -G plugins`.

The resulting `.so` runs only inside WSL's Linux Wireshark. A Windows
`.dll` targeting Windows-native Wireshark requires an MSVC toolchain
build against a Wireshark source tree matching the installed Windows
Wireshark version — cross-compiling from WSL to a Windows MSVC-
compatible DLL is not a clean path.

## Build (Windows, portable — no admin, no Visual Studio)

`scripts/win-portable-build.ps1` bootstraps a per-user toolchain (portable
MSVC + Windows SDK via [mmozeiko's portable-msvc.py](https://gist.github.com/mmozeiko/7f3162ec2988e81e56d5c4e22cde9977),
plus pinned CMake, Ninja, Strawberry Perl, and winflexbison), builds a
minimal Wireshark dev tree from source against it, and produces
`iccp.dll` — all without admin rights, without an installed Wireshark,
and without Visual Studio Build Tools. Everything lives under
`$HOME\.iccp-build\`.

```powershell
# First run (~10 min wall time): downloads MSVC + SDK + CMake + Ninja + Perl
# + winflexbison, builds Wireshark 4.2 libs, then iccp.dll. Installs to
# %APPDATA%\Wireshark\plugins\4.2\epan\.
.\scripts\win-portable-build.ps1

# Target a different Wireshark minor (each version's dev tree is cached
# separately under %BuildRoot%\ws-{src,build,install}-<minor>):
.\scripts\win-portable-build.ps1 -WiresharkBranch release-4.4
.\scripts\win-portable-build.ps1 -WiresharkBranch release-4.6

# Re-runs are fast (~5 sec) — only Phase 3 (the plugin compile) re-runs
# if Phase 1 (toolchain) and Phase 2 (Wireshark dev tree) are cached.
```

Useful flags: `-WiresharkDevTree <path>` to skip Phase 2 and reuse a
pre-built dev tree; `-SkipInstall` to leave the DLL in the build dir;
`-ForceMSVC` / `-ForceWireshark` to redo Phase 1 / 2.

Requires Python 3 on PATH (Mambaforge / standard installer / Microsoft
Store all work) — the portable-MSVC fetcher is a Python script.

## Build (Windows, native MSVC)

Two scripts automate the full path. Assumes you have already installed:

- Visual Studio 2022 Build Tools **with the "Desktop development with C++" workload**
  (this is not the default — add it via the VS Installer's Modify → workloads)
- CMake, Strawberry Perl, winflexbison, Python 3, Git

Then from a PowerShell prompt in the repo root, after setting the
`WIRESHARK_*` env vars (or passing them as parameters — see the
*Defaults* table below):

```powershell
# One-time per machine: tell the scripts where to build / install.
$env:WIRESHARK_SRC          = '<wireshark-source>'
$env:WIRESHARK_BUILD        = '<wireshark-build>'
$env:WIRESHARK_INSTALL_DIR  = '<wireshark-install>'
$env:WIRESHARK_LIBS_DIR     = '<wireshark-libs>'

# One-time (~5 min): clone Wireshark 4.2 source, download prebuilt deps,
# build libwireshark/libwsutil/libwiretap, install headers+libs+cmake config.
.\scripts\win-build-wireshark.ps1

# Every time you change plugin source (~30 sec): build iccp.dll and
# install to %APPDATA%\Wireshark\plugins\<X.Y>\epan\
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

| Parameter / env var                                   | Contents                                                                                        |
|-------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `-SourceDir`  / `$env:WIRESHARK_SRC`                  | Wireshark source clone (shallow)                                                                |
| `-BuildDir`   / `$env:WIRESHARK_BUILD`                | Wireshark build tree (contains `run\RelWithDebInfo\tshark.exe`)                                 |
| `-InstallDir` / `$env:WIRESHARK_INSTALL_DIR`          | Wireshark install tree (headers, libs, `WiresharkConfig.cmake`)                                 |
| `-LibsDir`    / `$env:WIRESHARK_LIBS_DIR`             | Prebuilt Windows deps (glib, gnutls, …) from Wireshark's dev-libs site                          |
| `-PluginBuild` (defaults to `<repo>\build\iccp`)      | Plugin build tree producing `<config>\iccp.dll`                                                 |
| `%APPDATA%\Wireshark\plugins\<X.Y>\epan\iccp.dll`     | Installed location (post-install copy from `win-build-plugin.ps1`, unless `-NoInstall`)         |

There are no hardcoded path defaults — every script either reads the
matching env var or requires you to pass the parameter explicitly.
Example override on the command line:
`.\scripts\win-build-wireshark.ps1 -SourceDir D:\ws\src -InstallDir D:\ws\install`.

### Quick verification

The Wireshark source build produces a local `tshark.exe` at
`<wireshark-build>\run\RelWithDebInfo\tshark.exe`. The plugin is
ABI-locked to that version, so you can sanity-check without installing
a separate Wireshark runtime:

```powershell
$tshark = Join-Path $env:WIRESHARK_BUILD 'run\RelWithDebInfo\tshark.exe'
$pcap   = '.\pcaps\generated\iccp-phase1.pcap'
& $tshark -G plugins | Select-String iccp
& $tshark -r $pcap -d tcp.port==10102,tpkt -Y iccp | Select-Object -First 10
```

### Runtime coexistence with stock Wireshark

A plugin built against Wireshark 4.2 **does not load** into Wireshark 4.6
or any other minor version — the ABI is pinned via the `plugin_want_major`
/ `plugin_want_minor` symbols. Options:

- Use the `tshark.exe` from your own `<wireshark-build>\run\RelWithDebInfo\`
  build tree (matches the Wireshark version you cloned, GUI-less).
- Install a stock Wireshark 4.2.x installer from wireshark.org/download
  side-by-side with any other version, then copy `iccp.dll` into its
  `%APPDATA%\Wireshark\plugins\4.2\epan\`.
- Build for a different Wireshark minor version by re-running
  `win-build-wireshark.ps1 -Branch release-4.4` (etc.).

## Generating a test PCAP

No public ICCP PCAPs of meaningful quality are known (utilities guard
them as sensitive). Two generators are shipped with this repo, for
different purposes:

### `scripts/gen-pcap.sh` — coverage capture for the dissector regression suite

Uses `libIEC61850`'s MMS server + `mms_utility` client on localhost,
requesting TASE.2-reserved variable names across all nine Conformance
Blocks plus the Block-5 device state machine. The server returns
"does-not-exist" but the request PDU on the wire carries the ICCP
name, which is enough to exercise the dissector. Each request is its
own short-lived MMS association.

```bash
# requires libiec61850 built once under ~/src/libiec61850
bash scripts/gen-pcap.sh
```

Produces `pcaps/generated/iccp-phase1.pcap` (~280 packets covering all
9 Conformance Blocks, Device Control state-machine, and an SBO violation).

### `scripts/gen-iccp-pcap.py` — fictional realistic ICCP capture

A self-contained Python synthesizer (no libIEC61850, no network
privileges) that produces an ICCP capture structurally similar to
real-world utility-to-utility traffic — long-lived bilateral
associations, **`DefineNamedVariableList-Request` / `Response`
exchange** that declares each Transfer Set with stable
`(domain, listName, [variable items])`, then cyclic Block-2
InformationReports at 1 / 4 / 60 s periods that reference those
named data sets and carry float + quality-byte payloads,
occasional Write-Request control commands, mix of CYCLIC and
SPONTAN transfer sets — using a controlled fictional wordlist
(peer codenames `AURORA`, `BLAZE`, …; domains like `AURORA_BLAZE`;
datasets like `DS_ANA_M_Z_NRT`). RFC 5737 documentation IPs only.

```bash
python3 scripts/gen-iccp-pcap.py -o pcaps/generated/iccp-fictional.pcap
# default: 5 minutes simulated, 5 bilateral peers, ~2 400 packets
python3 scripts/gen-iccp-pcap.py --duration 60 --seed 7 -o /tmp/short.pcap
```

Because the DSD frames are on the wire, the dissector's auto-
discovery (v0.6.1) populates `iccp.point.name` for every report
out of the box — no UAT entry needed. Open the pcap in Wireshark
and the Recovered-points subtree shows `→ <variable name>` on
each row.

The output is suitable for sharing as a sample capture, for
demonstrating the dissector to ICCP engineers, or for regression
runs that benefit from realistic traffic shape (cadence, point-quality
distribution, multi-bilateral peer mesh) — none of which the
`gen-pcap.sh` coverage capture gives. Names are entirely fictional and
the pcap cannot be linked back to any real-world utility.

## Running the regression suite

```bash
bash tests/regression.sh
```

21 assertions covering all 9 Conformance Blocks, every tracked
operation, the Device-Control state machine, and the no-false-positive
guard (plain-MMS Initiate doesn't promote to Confirmed ICCP).

A separate Lua tap-listener smoke test `tests/verify_stats.lua` counts
ICCP frames via the iccp tap. Point it at any ICCP capture:

```bash
python3 scripts/gen-iccp-pcap.py -o pcaps/generated/iccp-fictional.pcap
tshark -2 -X lua_script:tests/verify_stats.lua \
       -r pcaps/generated/iccp-fictional.pcap -q
```

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

Real-world TASE.2 links associate once and stay up for days or weeks. A
capture that starts mid-session (the common case for utility operators
dropping a tap on a long-lived link) misses the Connect-Presentation
(A-ASSOCIATE) exchange that binds each Presentation Context Identifier
(PCI) to its Abstract Syntax OID. Without that binding, Wireshark would
show *"dissector is not available"* under ISO 8823 Presentation on every
MMS frame, and the ICCP layer would never see the data.

The plugin **auto-injects the canonical ICCP binding** (PCI 3 → MMS
abstract-syntax OID `1.0.9506.2.1` and `1.0.9506.2.3`) into Wireshark's
in-memory `pres.users_table` at handoff, so this just works for the
overwhelming majority of real captures with no manual configuration.
Open the pcap and the iccp tree, columns, filters, and stats populate.

### When auto-injection isn't enough

If a vendor uses a non-standard PCI for MMS (anything other than 3) or a
non-canonical abstract-syntax OID, you need to add a row manually. Find
the PCI and OID:

```bash
tshark -r your.pcap -T fields -e pres.presentation_context_identifier \
    | awk 'NF' | sort -u
tshark -r your.pcap -T fields -e pres.abstract_syntax_name | sort -u
```

Then either:

**Wireshark GUI**: Edit → Preferences → Protocols → **PRES** → **Users
Context List** → *Edit…* → *New*. Set *Context Id* to your PCI and
*Syntax Name OID* to `1.0.9506.2.1` (or the vendor OID you observed).
The preference persists in your profile.

**tshark / scripted**: pass the binding inline.

```bash
tshark -r your.pcap -o 'pres.users_table:"7","1.0.9506.2.1"' -Y iccp -V
```

Sanity check that MMS now dispatches:

```bash
tshark -r your.pcap -T fields -e frame.protocols | sort -u | grep mms
# expect: eth:ethertype:ip:tcp:cotp:ses:pres:iccp:mms
```

User-set bindings win over the plugin's defaults — if you have an
existing row for PCI 3, your value is kept.

## Mapping point slots to variable names (DSD UAT)

MMS InformationReports identify each value only by its **position in
`listOfAccessResult`** — there's no per-point name on the wire. The
mapping `slot → variable name` lives in the **Data Set Definition**
that the bilateral peers negotiated at session setup. Concretely a
real cyclic transfer set might look like:

```
Slot 0: TS_NAME_REFLECTION       (visible-string, header)
Slot 1: SEQUENCE_COUNTER         (unsigned, header)
Slot 2: FREQ_BUS_EXAMPLE_BUS    (struct: float + quality byte)
Slot 3: GEN_MW_EXAMPLE_PLANT_G1       (struct: float + quality byte)
…
Slot 143: TIE_FLOW_NORDPOOL_HVDC (struct: float + quality byte)
```

If the capture covered the negotiation, the slot-to-name mapping is
derivable from the corresponding `DefineNamedVariableList-Request` PDU
on the wire (auto-capture into the plugin's lookup table is a roadmap
item — currently you'd inspect that PDU manually). For
mid-session captures (the common case), populate the mapping yourself
in **Edit → Preferences → Protocols → ICCP → DSD (Data Set Definition)
variable-name mapping**:

| Domain | Transfer Set | Slot | Variable Name |
|---|---|---|---|
| `EXAMPLE_DOMAIN` | `EXAMPLE_DATASET` | 2 | `FREQ_BUS_EXAMPLE_BUS` |
| `EXAMPLE_DOMAIN` | `EXAMPLE_DATASET` | 3 | `GEN_MW_EXAMPLE_PLANT_G1` |
| `EXAMPLE_DOMAIN` | `EXAMPLE_DATASET` | 4 | `VOLT_LINE_EXAMPLE_LINE_KV` |
| … | … | … | … |

Once the mapping is loaded, every Point #N in the recovered subtree
carries a `[Name: <variable name>]` child (filterable as
`iccp.point.name`), and the parent row text becomes `Point #N: <value>
[quality]  →  <variable name>` so you can scan without expanding.

The mapping persists as `iccp_dsd` in your Wireshark profile; you can
also create / edit the file directly with one row per line — note
that **all four fields must be quoted, including the slot number**:

```
"EXAMPLE_DOMAIN","EXAMPLE_DATASET","2","FREQ_BUS_EXAMPLE_BUS"
"EXAMPLE_DOMAIN","EXAMPLE_DATASET","3","GEN_MW_EXAMPLE_PLANT_G1"
```

(The GUI editor handles the quoting automatically — only the script /
file-bulk-import case needs to know.)

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
6. **Wireshark's MMS dissector aborts on multi-item reports — fixed
   upstream in 4.2.3.** Versions 4.2.0 / 4.2.1 / 4.2.2 have a
   recursion-depth bookkeeping bug in
   `epan/dissectors/packet-mms.c:dissect_mms_Data` (and
   `dissect_mms_TypeSpecification` / `dissect_mms_AlternateAccess` /
   `dissect_mms_VariableSpecification`). Each function captures the
   pre-call `recursion_depth`, increments by `cycle_size` for the
   recursion, and on return *subtracts* `cycle_size` from the captured
   baseline — wrapping an unsigned counter on the very first call.
   The next dissect_mms_Data sees a huge depth and `DISSECTOR_ASSERT
   (recursion_depth <= MAX_RECURSION_DEPTH)` fires, aborting MMS
   dissection. On real ICCP traffic this triggers on essentially every
   InformationReport because every report is a `SEQUENCE OF` recursing
   `dissect_mms_Data` per element. The fix in 4.2.3 (one-line change
   per function) restores `recursion_depth` to the captured baseline
   instead of subtracting. The plugin works around the bug on still-
   buggy versions in two places:
   (a) `iccp_dispatch_via_oid` wraps `call_dissector_only(mms_handle,
   …)` in `TRY/CATCH(DissectorError)` so the assertion is absorbed
   before Wireshark's outer dispatcher can paste the bug text into
   `col_info`;
   (b) a hand-rolled BER walker (`iccp_ber_recover`) decodes
   `listOfAccessResult` / `listOfData` directly from the PDU bytes,
   walks structures and arrays recursively, and feeds the same
   counters and point arrays the proto-tree path uses, so floats and
   quality bytes past item 2 still feed the stats, the tap, and the
   `Recovered points` subtree. The header text auto-adapts based on a
   per-frame BER-vs-tree-count comparison: "Recovered points: N — MMS
   truncated this frame" on buggy Wireshark, "Per-point listing: N
   (parallel view)" on 4.2.3+.
7. Plugin handoff calls `iccp_inject_pres_binding` to add the canonical
   ICCP context binding (PCI 3 → MMS abstract-syntax `1.0.9506.2.1`)
   into the in-memory `pres.users_table`. This makes mid-session
   captures (which miss the AARQ) dispatch to MMS without manual
   preference configuration. User-set entries for the same PCI win.
8. **`iccp.point.value` and `iccp.value.real` are FT_DOUBLE since
   v0.6**, not FT_FLOAT. Right-clicking on a displayed point value and
   choosing *Apply as Filter* puts e.g. `iccp.point.value ==
   4440.14013671875` into the bar; with single-precision storage this
   would have rounded to `4440.14` for display, and the literal
   `4440.14` doesn't compare equal to the stored `4440.140136…` value
   when promoted to double. Storing as double means the displayed text
   IS the stored value, so the round-trip works.
9. **`iccp.point.slot` and `iccp.point.index` are different and both
   useful.** `slot` is the 0-based position in `listOfAccessResult`
   (the wire position used in bilateral table documentation); `index`
   is the 1-based ordinal among recovered floats (skips header items
   like sequence counters and timestamps). For correlating to operator
   docs, use `slot`. For "the Nth float", use `index`.
10. **Truncation detection compares `mms.AccessResult` /
    `mms.structure` / `mms.floating_point` / `mms.data_bit-string` from
    the proto tree against the BER walker's counts.** Note that the
    actually-emitted abbrev for the structure-count is `mms.structure`
    in 4.2.x and 4.6 alike — the duplicate `hf_mms_structure` field
    registered with abbrev `mms.structure_element` is never actually
    emitted. The plugin matches both names defensively.

## License

GPL-2.0-or-later (SPDX: `GPL-2.0-or-later`), matching Wireshark's
own license.
