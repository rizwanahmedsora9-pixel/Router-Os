# Installed-version and WDS status baseline — 2026-09-21

## User-reported observation (not independently polled)

| Field | Reported value | Interpretation |
|---|---|---|
| Firmware | `4.19.55 Build 160426 Rel.73431n` | Strongly corroborated by repository bytes; see static analysis below |
| Hardware | `WR720N 2.0 00000000` | Consistent with the previously supplied EU Ver: 2.0 label |
| Wireless radio | Enabled | Operational observation, not a capability enumeration |
| Channel / mode / width | 13 / 11bgn mixed / 20 MHz | Current values to preserve during diagnosis, not universal profile defaults |
| WDS status | Run | Firmware-reported state, not independently verified forwarding |
| WAN | Dynamic IP; unplugged; address, mask, gateway and DNS all zero | Do not require Ethernet WAN acquisition to verify a WDS connection |
| Traffic counters | Received/sent bytes and packets all zero | Counter scope/accuracy unknown; not proof that the bridge has no traffic |
| Uptime | 0 days, 01:01:37 | One observation, not evidence about prior saves or reboot-free switching |

Full MACs, SSID, LAN address and other device/network-specific identifiers are
intentionally omitted from committed project notes. The assistant did not connect
to the router. Its private LAN address is not reachable merely because it was
shared in chat; no sandbox request to that address was attempted.

**Important distinctions:** the Status page's Wireless MAC is the local device
MAC, not the upstream BSSID. Its Name (SSID) display is populated from local SSID
entries (`StatusRpm.htm:185–203`), not a reliable source for the bridged peer SSID.
Do not construct a saved WDS profile from these fields. The local management LAN
address/mask must remain unchanged; DHCP role, actual bridge membership, upstream
address and routing still need observation rather than inference.

## Installed-build correlation from the repository

Image 2, `wr720n/unpacked-os/v2.0-160426/vxworks-image-2/main-code.bin`, contains:

- Offset `0x2ca574`: `Apr 26 2016`.
- Offset `0x2ca580`: `20:23:51`.
- Offset `0x2ca5f0`: `%d.%d.%d Build %02d%02d%02d Rel.%d%c%c`.
- At candidate address `0x8000dc58`, a formatter references these routines/data;
  it passes `n` and a trailing space for the last two characters.
- The date/time parser at candidate address `0x8000d87c` computes the release
  value as seconds since midnight: `(20 * 60 + 23) * 60 + 51 = 73431`.
- Stock-container offsets `0x24` and `0x400a4` contain `5a 04 13 37`. The low
  three bytes are decimal **4, 19, 55**. The formatter obtains the version word
  through a getter; tracing its initialization from the header remains pending.

This is strong corroboration of the **full reported version**, beyond matching
only the filename's build number. It does not establish byte-identical installed
flash, an unchanged bootloader, driver ABI compatibility, or safe upgrade/recovery.
The existing tool labels this header field `load_addr`; the new evidence suggests
that interpretation merits investigation. No parser or header field was changed.

## Static WDS Save-path progress

Analysis tool: Capstone 5.0.7, MIPS32 big-endian, on the host only. No firmware
code was run. Candidate virtual address mapping is `image-2 file offset +
0x80001000`, consistent with the repository's prior mapping and observed string
references. Addresses below are **reverse-engineering leads, not a callable API**.
Complete decoded ranges and input hashes are in
[research/status-static-trace.txt](research/status-static-trace.txt).

| Candidate address | Static evidence | Confidence / limits |
|---|---|---|
| `0x802aede4` | References `WlanNetworkRpm`, supplies `/userRpm/WlanNetworkRpm.htm` and callback address `0x802ae3d8` to a shared routine | Likely page registration; shared routine ABI not fully recovered |
| `0x802ae3d8` | Page callback candidate; references `Save` at image offset `0x2e78c4`; a nonzero lookup result reaches call `0x802adae0` | Strong Save dispatch lead; all dispatch preconditions remain to be traced |
| `0x802adae0` | Reads existing configuration into several stack areas, parses/validates request parameters; normal tail calls `0x8026e760`, `0x8026e810`, `0x8026e93c`, then `0x8027746c` | Candidate settings Save implementation, not an atomic switch coordinator |
| `0x8026e760` → `0x80251820` | First wrapper/body compares and conditionally copies a `0xb0`-byte structure, writes 1 to candidate global `0x8037c6e4` | Changed-data flag lead; flag readers, lock semantics and radio side effects not resolved |
| `0x8026e93c` → `0x80251dac` | Third wrapper/body includes a conditional additional call, then compares/copies `0x7a` bytes and sets the same global | Coupled configuration path; extra operation and structure layout still require analysis |
| `0x8027746c` → `0x802484c4` → `0x80248514` | Final call path builds a header/checksum-like value and invokes lower-level routines | Persistence candidate, not proof of atomic storage, flash geometry or power-loss recovery |

The Save handler's normal tail (`0x802ae388` through `0x802ae3ac`) does not branch
on those setter/final-call return values before returning zero. This is a **local
control-flow observation**, not a claim that no internal checks exist in callees.
It is insufficient for verified all-or-nothing profile switching. Never interpret
an HTTP success or zero handler return as proof that WDS connected successfully.

No no-reboot path, safe driver calling convention, peer-only restart scope,
rollback sequence or flash transaction was established. The conditional reboot
warning in the stock page remains relevant. Do not patch out the warning, replay
Save as a transaction, call these addresses, or disable a watchdog.

### Reproduce the offline evidence

Install `capstone==5.0.7` in a host-only analysis environment, not on the router.
Use Python's `capstone.Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)` and
`disasm(image[start-base:end-base], start)`, where `base = 0x80001000`. Each range
and raw instruction word is recorded in the trace; ranges end exclusively.
Verify the trace's input SHA-256 first. Re-read NUL-terminated strings at the file
offsets above. Check raw header bytes in the **container**, not the decompressed
image. This is static evidence reproduction, not hardware emulation or testing.

## Consequences for the profile design

- A current Run indication is a baseline observation, **not an active saved profile**;
  no profile store or active ID has been created.
- Verify candidate connections using expected upstream BSSID, security completion,
  channel and actual bridge forwarding. Preserve wired management and existing LAN
  services. Do not require the unused WAN port or public Internet access.
- Confirm a reachable upstream test target appropriate to this LAN. A single
  blocked ICMP probe must not be the only test or force a false rollback.
- Do not infer upstream BSSID, security/key, WDS options or interfaces from the
  local Status page. Obtain those via read-only settings/diagnostics later.
- Preserve the current fixed channel/width until capability/regulatory data is
  known. Channel 13 being displayed does not authorize arbitrary region changes.
- Measure same-channel and cross-channel switching separately. With a shared
  radio, a retune may interrupt local AP clients; staging/zero interruption has
  not been demonstrated.

## Smallest next safe checks

**No Save, Survey, reboot, firmware upload, reset or Restore is needed.**

1. Confirm whether an Ethernet-connected computer can reach the router through a
   **LAN** port. If administration is wireless-only, live wireless changes are blocked.
2. Confirm that the stock `config.bin` backup has been saved privately. Do not
   upload it or a browser HAR: both may expose credentials. A configuration backup
   is not a full flash/recovery backup.
3. Confirm whether a client currently passes traffic through WDS despite the WAN
   being unplugged, using ordinary existing traffic rather than changing settings.
4. If needed next, open Wireless Settings without saving and report only the WDS
   key-type label, whether a reboot warning is already visible, and whether local
   AP clients are in use. Do not send passwords or a full page-source dump; the
   stock page can embed the key in `wlanPara`.

Read-only page observation does not replace driver/SDK, console/boot evidence,
flash layout and recovery validation. Lack of console/spare hardware must be
reported as a limitation, not bypassed by unsafe remote experiments. The user
has already supplied the label and complete Status version; do not ask for them again.
