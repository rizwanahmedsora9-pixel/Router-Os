# Wds profile os

**Stage: label and reported firmware version matched; safe driver apply/restore still unverified.**

A separate, minimal-change WDS profile project for the firmware already in this
repository. No application code, driver patches, UI changes, or flashable firmware
have been made. This is not yet a working profile manager.

## Start here

- [STATUS-BASELINE.md](STATUS-BASELINE.md): reported installed version/WDS state,
  binary version correlation, and initial Save-handler disassembly.
- [AUDIT.md](AUDIT.md): findings, exact evidence, and unknowns.
- [HARDWARE-FOLLOWUP.md](HARDWARE-FOLLOWUP.md): label confirmation, model-family
  chipset evidence, upgrade constraints, and remaining runtime gates.
- [ARCHITECTURE.md](ARCHITECTURE.md): proposed profile manager and safe switching design.
- [HARDWARE-CHECKLIST.md](HARDWARE-CHECKLIST.md): evidence required before coding.
- [BACKUP-AND-TESTS.md](BACKUP-AND-TESTS.md): pre-change backup, rollback, and test results.
- [research/](research/): baseline hashes, firmware inspection, binary-string offsets,
  WDS web-source excerpts, and offline test results (2026-09-21).

## Important findings

The repository targets **TP-Link TL-WR720N (EU) V2**, build **160426**. The supplied
image contains **VxWorks 5.5.1** and Atheros AR933x/AP121/vendor-driver references,
not a Linux/OpenWrt root filesystem. The user-reported label now confirms
**TL-WR720N(EU) Ver: 2.0**, FCC ID **TE7WR720NV2**. The user reports
`4.19.55 Build 160426 Rel.73431n` / `WR720N 2.0 00000000`; binary date/time and
header evidence strongly corroborate the match. Installed flash bytes, exact
driver version and live-update capabilities remain unverified. Model-family
chipset/resource evidence and its limitations are recorded in the follow-up. The WDS form already accepts a manually entered peer, but
includes a conditional reboot-required warning. Runtime ioctl strings are leads,
not proof of safe live switching.

**Do not flash the existing v1 probe or a newly repacked image for this project.**
Offline container verification does not establish upgrade acceptance, hardware
compatibility, recovery, or runtime safety.

## Interface policy

Keep the stock frame layout, styling, navigation, and existing management pages.
Eventually add only a WDS Profiles entry under Wireless, a compact profile table,
and inline switching status. No redesign or replacement of working components.
The proposed implementation is gated on hardware, runtime, persistence, and
recovery evidence; see the checklist.
