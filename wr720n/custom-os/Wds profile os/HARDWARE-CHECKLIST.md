# Hardware gate — information needed before implementation

## First, obtain without changing the router

1. **Received:** user-reported label confirms TL-WR720N(EU), Ver: 2.0,
   FCC ID TE7WR720NV2. See [HARDWARE-FOLLOWUP.md](HARDWARE-FOLLOWUP.md).
   Do not resubmit serial number, MAC, WPS PIN or credentials.
2. **Received:** `4.19.55 Build 160426 Rel.73431n` and
   `WR720N 2.0 00000000`; WDS reports Run on channel 13 / 20 MHz. See
   [STATUS-BASELINE.md](STATUS-BASELINE.md). Do not request the version again.
3. Use the stock **System Tools → Backup & Restore → Backup** and keep `config.bin`
   privately in two locations. It may contain passwords; do not post it publicly.
   Record its hash locally. Do not invoke Restore for the initial audit.
4. Describe working WDS settings (without passwords), upstream AP model/security,
   local AP use, and whether existing saves show a reboot warning. Record observed
   behavior from prior use; do not run a disruptive test on the production network.
5. Say whether a spare router, wired LAN administration, and a safe maintenance
   window are available. A console/boot log or compatible vendor SDK is particularly
   useful. No Linux SSH commands or shell access are assumed.

## Bench-only expert investigation

- Verify physical chipset/radio/flash/RAM markings or reliable board identification.
  Do not open or wire a powered device. UART voltage and pinout must be established
  for this board before connection; never assume 5 V or copy another model's pinout.
- Capture an existing boot log where safely available; scheduling a reboot solely
  for collection requires a maintenance window. Identify installed bootloader,
  memory/flash layout, OS build, startup tasks, interface names and calibration areas.
- Through a validated read-only method, make a **full per-device flash backup**,
  including bootloader, configuration, factory MAC/calibration data. Verify two
  copies/hashes. The vendor upgrade `.bin` is not this backup.
- Establish the exact recovery transport and a tested procedure on a spare unit.
  Repository mentions of TFTP or a generic upgrade PDF do not establish recovery.
- Obtain compatible SDK/source/symbols or a defensible reverse-engineered ABI and
  build/upgrade-validation path. Map management-handler save/apply operations to
  configuration persistence, wireless calls and task restarts.
- Enumerate radio capabilities, security/cipher support, channel restrictions,
  shared-radio AP/WDS interactions, VAP limits and scan behavior. Determine whether
  saved-peer acquisition can avoid a full scan and whether staging is supported.
- Establish independent status/verification and reversible runtime operations for
  BSSID, SSID, keys, channel, width, WDS and bridge changes. Resolve ioctl arguments,
  task context, ordering, callbacks, timeouts and restoration; never call guessed APIs.
- In an isolated bench, compare before/after config and task state for each change.
  Monitor wired LAN, DHCP, routing, firewall, upstream and AP clients. Record any
  necessary radio restart and measured interruption. No whole-stack restart fallback.
- Validate writable space, erase units, wear limits, atomicity and crash recovery
  before selecting a persistent profile-store format.

## Gate completion record (label/version received; safe switching still pending)

| Evidence | Required result |
|---|---|
| Label identity | Received: TL-WR720N(EU) Ver: 2.0 / TE7WR720NV2 (user report) |
| Chipset / resources | Model-family reference corroborates AR9331; actual board/resources need verification (see follow-up) |
| Installed firmware | Reported full version matches repository date/time/header evidence; installed flash bytes not compared |
| Driver/SDK or verified ABI | Proven runtime capabilities and safe apply/restore path |
| Existing WDS handler trace | Initial static Save-dispatch/setter trace recorded; runtime effects and actual restart scope unresolved |
| Storage and backups | Private verified backups, safe writable area, power-loss protocol |
| Recovery | Documented and demonstrated on matching spare hardware |
| Timing and dependency tests | Measured unavoidable interruption and unaffected services |

Next user checks: wired LAN administration, private configuration backup, and
actual WDS client forwarding (see status baseline). No wireless changes are
authorized by these observations alone.

Only after the required gates are met, start architecture step 1. If any safe live-update primitive is absent,
report the unsupported feature and required vendor/backend work; do not disguise
rebooting or simple form submission as seamless switching.
