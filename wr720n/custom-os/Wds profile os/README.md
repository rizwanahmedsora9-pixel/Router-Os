# Wds profile os

**Stage: a buildable image exists (WDOS 1.0, `release/`); safe driver apply/restore is
still unverified, and no hardware has been touched.**

A separate, minimal-change WDS profile project for the firmware already in this
repository. WDOS 1.0 is the official 160426 image plus a browser-side WDS preset row on
the stock Wireless page: no driver patches, no kernel/application-code changes, and no
attempt at live switching. Only four of the 194 files in the management web filesystem
differ, and the boot partition, application code stream and trailing blob are copied
unchanged. See [release/README.md](release/README.md) for what that does and does not
prove before flashing anything.

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
- [research/vendor-upgrade-acceptance.md](research/vendor-upgrade-acceptance.md): the
  recovered length / md5 / header rules the router applies to an uploaded image, and how
  they were reproduced offline.
- [release/README.md](release/README.md): the built image, its hashes, exactly what it
  changes, the evidence behind it, and its unproven parts.
- [payload/](payload/): the HTML/JS fragment that is injected into the stock page.
- [tools/](tools/): `wdos_build.py` (build, vendor-acceptance `check`, `layout`) and
  `wdos_verify.py` (host-side verification harness). Both are stdlib-only except for the
  optional `node` used for JavaScript syntax checks.

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

**Do not flash the existing v1 probe** (`../v1/wr720nv2-eu-up-v1-probe.bin`): it was
built before the vendor acceptance rules were recovered, its size differs from the
official image, and nothing verifies it.

The WDOS 1.0 image in `release/` is a different case: it reproduces the vendor's own
acceptance scheme offline and changes nothing outside the management web filesystem.
It is still **not hardware-validated** - no unit has been flashed in this project -
so treat flashing it as an experiment you must be able to recover from. The full risk
statement is in [release/README.md](release/README.md); read it first.

## Interface policy

Keep the stock frame layout, styling, navigation, and existing management pages.
WDOS 1.0 follows this: it adds one `WDS Profiles` row inside the existing WDS field
table on `WlanNetworkRpm.htm`, using the stock `Item` / `button` classes and the stock
`doBrl()` / `doSelKeytype()` helpers, and it leaves the page's own tables, form and Save
button alone. The row is visible exactly when the WDS fields it fills in are visible.

The wider profile manager (profile table, inline switching status, live switching) is
still gated on hardware, runtime, persistence, and recovery evidence; see the checklist.
Nothing in this project performs a live switch, and `Run` on the Status page is not
accepted as proof that a WDS link works.
