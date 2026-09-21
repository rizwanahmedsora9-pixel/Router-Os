# Label-confirmed hardware follow-up — 2026-09-21

## What the user supplied

The user transcribed the device label. Record only non-device-unique facts:

| Item | Label value | Confidence |
|---|---|---|
| Model / region / version | TL-WR720N(EU), Ver: 2.0 | User-reported label; matches repository target |
| FCC ID | TE7WR720NV2 | User-reported regulatory model identifier |
| Supply | 5 V DC, 0.6 A | Label specification, not a measured operating budget |

Serial number, full MAC, WPS PIN, default SSID and credentials are intentionally
not copied into this project. No router connection, firmware save, reboot or
configuration mutation was performed. Installed firmware was unknown at this
label-only stage; the subsequent [STATUS-BASELINE.md](STATUS-BASELINE.md) records
the reported full version and new static analysis.

## External corroboration, not a per-device probe

The model-specific WikiDevi entry associates TE7WR720NV2 with the following
hardware. It covers v2.x and includes a **rev-2.1** board example; this is supporting
evidence for the user's **v2.0** label, not proof that every part is identical.
[10](https://wikidevi.wi-cat.ru/TP-LINK_TL-WR720N_v2)

| Component | Reported for model family | Remaining confirmation |
|---|---|---|
| SoC / wireless | Atheros AR9331, 802.11b/g/n, 1x1:1 | Exact installed silicon and driver capabilities |
| Flash | 2 MiB, GigaDevice GD25Q16CSIG | Chip/revision, usable space, erase geometry, partition map |
| RAM | 16 MiB, Zentel A3S28D40JTP-50 | Actual installed/available RAM and runtime headroom |
| Ethernet | Two LAN ports, one WAN, 100 Mbps | Live interface names, port mapping and bridge membership |
| Stock OS | VxWorks 5.5.1 | Installed build; repository binary is already independently identified |

Source for all reported values in this table:
[10](https://wikidevi.wi-cat.ru/TP-LINK_TL-WR720N_v2).
The repository's AR9331 BSP paths and VxWorks strings corroborate the family,
but neither the label nor a web reference establishes a runtime driver ABI.
Do not turn these memory sizes or interface counts into hard-coded configuration.

The same reference contains RU-firmware offsets and serial/flash instructions.
These have **not** been validated for this EU v2.0 unit and are deliberately not
copied as executable recovery instructions.
[10](https://wikidevi.wi-cat.ru/TP-LINK_TL-WR720N_v2)

The FCC index search result lists internal photographs for TE7WR720NV2.
[1](https://fccid.io/TE7WR720NV2)
Direct retrieval of both FCC mirrors returned a security-check page. No internal
photograph was examined, so there is no FCC-photo-based chip confirmation here.

## Vendor upgrade constraint

TP-Link's V2 support page lists EU build 160426, warns that configuration will
be lost on upgrade, and says this EU version cannot be downgraded to another
version. It also lists older build 141118; its presence is not evidence that a
particular installed device can safely downgrade.
[5](https://www.tp-link.com/in/support/download/tl-wr720n/)

Consequences for this project:

- Do not upgrade or downgrade simply to collect audit evidence.
- A saved vendor image is an analysis baseline, **not guaranteed flash rollback**.
- Prove same-build recovery/acceptance on matching spare hardware before any patch.
- Keep a private stock configuration backup and, through a validated method, a
  full per-device flash/calibration backup before firmware experiments.
- No claim is made that a complete compatible SDK is available. The support page's
  generic GPL notice/link is not proof of vendor driver source or a working build
  toolchain. [5](https://www.tp-link.com/in/support/download/tl-wr720n/)

## Additional local runtime leads

Fresh inspection of repository image 2 yielded the following strings; exact
extract is saved in `research/runtime-leads.txt`. Offsets are **data-string file
offsets in decompressed image 2**, not addresses safe to call.

| Offset | String | Investigation target, not a confirmed API |
|---|---|---|
| `0x2d13fc` | `wlaninfo` / show WLAN info | Possible live radio/capability diagnostics |
| `0x2d1450` | `showScan` / layout scan result | Possible cached survey result display; side effects unproven |
| `0x2d17f8` | `memShow` | Resource inventory |
| `0x2d1838` | `task` / print task information | Task/restart dependency inventory |
| `0x2d18b8` | `ifShow` | Interface inventory |
| `0x2d1980` | `bridgeShow` | Bridge inventory |
| `0x312c7c` | `wlan_set_channel` | Runtime channel setter lead |
| `0x313924` | `wlan_set_chanswitch` | Channel-switch path lead |
| `0x31bc68` / `0x31bd24` | `wlan_mlme_start_bss` / `wlan_mlme_stop_bss` | Wireless BSS lifecycle leads |
| `0x31bee0` | `wlan_mlme_connection_reset` | Wireless reset scope lead |
| `0x327ee0` / `0x327f28` | `wlan_connection_sm_start` / `wlan_connection_sm_stop` | Driver connection state-machine leads |
| `0x3291ac` / `0x3291f0` | `wlan_assoc_sm_start` / `wlan_assoc_sm_stop` | Driver association state-machine leads |
| `0x330c98` | `apcfg_wlan_start` | Vendor wrapper/startup path lead |
| `0x34b964` | `wlan_ioctl[IEEE8211IOCTL_SETFREQ]` | Frequency ioctl diagnostic (spelling as stored) |

These strings support investigating a wireless-scoped transition rather than a
whole-network restart. They do **not** prove reachable functions, a no-reboot
configuration path, safe sequencing, successful rollback, or a downtime bound.
No guessed call, ioctl, shell command or device-memory access was executed.
Do not run the listed diagnostics until console availability and command semantics
are established; a string that says "show" does not prove absence of side effects.

Next reverse-engineering work, once the installed build is established: trace
wireless settings save handlers and reboot-flag setting to vendor configuration
writes and wrapper calls; recover arguments/callback/task context; then validate
read-only diagnostics and apply/restore on a bench. Driver-internal state machines
are not a substitute for a persistent profile transaction coordinator.

## Current gates and next user input

1. **Label identity: satisfied by user report.** No need to resubmit identifiers.
2. **Chipset: model-family corroborated; installed board not directly examined.**
3. **Installed version: subsequently received.** `4.19.55 Build 160426
   Rel.73431n` / `WR720N 2.0 00000000`. See the status baseline for binary
   corroboration. No installed flash-byte comparison was performed.
4. **Driver apply/restore ABI, exact WDS save behavior, restart scope, storage
   atomicity and physical recovery: pending.** An existing boot log/SDK or safe
   console access on a spare unit would help; do not create an outage to obtain it.

Implementation remains gated. The design and original UI remain unchanged; no
flashable image or working profile manager is claimed.

## Sources and retrieval notes

Consulted on 2026-09-21:

- [10](https://wikidevi.wi-cat.ru/TP-LINK_TL-WR720N_v2): retrieved model-specific
  hardware table and revision notes; secondary community evidence.
- [5](https://www.tp-link.com/in/support/download/tl-wr720n/): retrieved V2 page at
  `https://www.tp-link.com/in/support/download/tl-wr720n/v2/`, including firmware
  notes; vendor publication, not a live-device query.
- [1](https://fccid.io/TE7WR720NV2): indexed exhibit listing only; direct fetch and
  `https://fcc.report/FCC-ID/TE7WR720NV2` returned security checks. No photo evidence.

This document records the relevant findings, their provenance and limitations;
external pages may change. Original binary evidence remains hash-anchored in the
repository and pre-change backups.
