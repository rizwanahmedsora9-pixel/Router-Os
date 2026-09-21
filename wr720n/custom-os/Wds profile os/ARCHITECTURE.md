# Proposed architecture — not implemented

This is a conditional design, not a claim that the vendor firmware supports it.
No Linux daemon, shell command, ioctl number, flash address or radio name is
assumed. Reuse the stock VxWorks BSP, wireless driver and network services.
If a compatible SDK/backend extension path cannot be established, stop and
report that constraint rather than shipping a browser-only substitute.

## Components and order

Each step needs a file list, explanation, reversible patch, tests and a recorded
result before the next step begins. Future paths below are tentative, within
this project directory; no stock/extracted files are edited in place.

| Step | Planned files/component | Gate and tests | Rollback |
|---|---|---|---|
| 0 (this change) | README, audit, design, checklist, backup/tests, research | Offline integrity and source evidence; runtime gate still open | Remove only this project's additions |
| 1 | `driver/` capability report and read-only adapter | Confirm hardware/ABI; enumerate interfaces, state and limits without mutations; reject unknown hardware/build | Remove adapter; no configuration change |
| 2 | `profiles/` router-side model, validation, persistence | CRUD, duplicate/rename/enable/disable, secret handling, limits; storage failure and torn-write injection | Preserve prior valid schema/generation; no destructive migration |
| 3 | `switch/` coordinator with simulated adapter and tests | Every state/failure edge, concurrency, deadlines, stale callbacks and power recovery; then isolated hardware tests | Disable switch entrypoint; retain verified last-good config |
| 4 | `webroot/` copies of the few required stock assets | Add small WDS Profiles view; test escaped input, auth/CSRF, status accuracy, no automatic scan | Restore original changed assets; no navigation redesign |
| 5 | `backup/`, diagnostics, release validation | Restore validation, resource/soak/fault tests; upgrade acceptance and proven physical recovery | Known-good image plus per-device config/calibration backups |

No target executable or image should be generated until the toolchain, image
validation, space budget and hardware recovery procedure are established.

## Profile model

Router-side, versioned, bounded records with stable opaque IDs, unique display
names, enabled flag, revision and compatible capability/build identifier:

- Peer SSID (driver-supported byte encoding/length), normalized unicast BSSID,
  channel/frequency, width, mode and regulatory compatibility.
- Security/authentication/cipher settings, protected key reference and supported
  legacy WEP slot/type if needed. Never silently downgrade security. Warn on
  weak legacy security and only offer modes actually supported.
- WDS/4-address/bridge options; discovered radio/interface IDs and bridge binding.
- A versioned, allowlisted driver-extension section for required vendor options;
  reject unrecognized options rather than sending arbitrary settings to the driver.
- Optional scan metadata and timestamp, separate from saved connection parameters.

The stock form is a starting field map, not a complete model. Separate local AP
configuration from peer configuration so switching cannot accidentally overwrite
LAN/AP settings. Shared-radio constraints must be visible and validated.

Duplicate creates a new ID, never an active duplicate. Rename changes metadata
only. Delete/disable of an active or in-flight profile is rejected until a verified
replacement is selected (or a separately confirmed disconnect operation exists).
Editing an active profile creates a candidate revision; it does not silently
mutate the currently verified revision. Enforce bounded count, size and memory
use after measuring device capacity. No browser-only authoritative storage.

## Capability adapter

Define and prove contracts before binding them to vendor functions:

- Read capabilities/current effective configuration and association state.
- Compute supported minimal delta and impact (peer, authentication, radio, bridge).
- Capture restorable state; prepare, apply, connect, cancel and restore.
- Verify expected BSSID/channel/security, association and actual bridge reachability.
- Read status/errors without forcing scans or writes.
- Explicit user-requested survey; results never overwrite a profile without confirmation.

A saved known BSSID/channel is used directly. Never open Survey or fall back to a
full discovery scan on Connect. Driver-internal targeted acquisition may still be
needed; distinguish it from full surveys and report measured behavior. An unknown
or stale channel fails with an explicit option to Scan/Update, not a hidden scan.

## Switching state machine

```text
CURRENT -> PREPARE -> APPLY -> CONNECT -> VERIFY -> COMMIT -> CURRENT(new)
              |         |         |         |         |
              +---------+---------+---------+---------+--> failure handling

Before mutation: abort -> CURRENT(old)
After possible mutation: ROLLBACK -> verify restored old -> CURRENT(old)
Rollback cannot be verified: DEGRADED (explicit error, preserve LAN access)
```

1. **CURRENT:** display configured last-good profile separately from observed live
   connection. A historical active ID is not proof that the radio is connected.
2. **PREPARE:** serialize switches and conflicting wireless configuration writes.
   Reject stale profile revisions/disabled profiles; validate capabilities, keys,
   regulatory settings and resources. Capture actual prior configuration, not just
   its profile ID. Reserve rollback resources and durably record intent before
   changing hardware. No changes on validation/journal failure. Same effective
   configuration is a verified no-op, not a radio reset.
3. **APPLY:** change only the computed delta. Stage a separate peer/VAP only if
   driver support and resource/isolation tests establish safety. Otherwise perform
   a bounded break-before-make transition limited to the affected wireless scope.
   No reboot or whole-stack/service restart fallback. If such a restart is required,
   report unsupported live switching instead.
4. **CONNECT:** target the saved peer directly; use bounded driver operations and
   explicit monotonic deadlines. Preserve the last-good active record while pending.
5. **VERIFY:** check a fresh expected-peer association, channel and authenticated
   security state, bridge membership, and LAN-side traffic to an appropriate upstream
   test target. No universal public-internet ping requirement: isolated upstream
   networks can be valid. Prevent stale status events from verifying another attempt.
   Sample LAN/DHCP/firewall/routing health without restarting them.
6. **COMMIT:** only after verification, atomically persist the new last-good revision
   and transaction completion with the supported storage mechanism, then publish the
   new active ID. Persistence failure triggers rollback. Power-cut recovery must
   deterministically distinguish the previous committed generation from the new one.
7. **ROLLBACK:** cancel/drain candidate operations and late callbacks, restore prior
   effective wireless/bridge state and verify it within a deadline. Preserve prior
   durable last-good identity. If the old upstream disappeared or driver restoration
   fails, report DEGRADED/disconnected; never claim CURRENT or silently reboot.
   Keep wired administration and unaffected LAN services available. Retain both
   configurations and diagnostics for manual recovery; no unbounded retry loop.

Use transaction IDs, profile revisions, event generations and one mutation lock.
Browser disconnects must not cancel rollback supervision. A router-resident task
owns the transaction, not an open web page. Remote status reads remain available.

## Persistence and power failure

Investigate vendor configuration APIs and flash layout before allocating storage.
Prefer proven vendor atomic storage; otherwise evaluate two independent erase-unit
slots with schema, generation, length, checksum, readback and atomic commit marker.
Two files in one erase sector are not redundant. Checksums detect corruption, not
malicious changes. Keep calibration/boot partitions untouched. Validate available
space and flash write endurance; avoid writing on each poll or scan.

At boot, validate committed records and pending intent before bringing WDS up.
Use the last durable committed generation, discard incomplete candidates and verify
live state. Test power loss at each erase/write/commit boundary, including recovery
and rollback. Do not assume POSIX rename/fsync semantics exist on this firmware.

Backups are versioned, length/checksum validated and hardware/schema checked. Import
is staged, bounded and fully validated before mutation; never trust an imported
active ID or run configuration immediately. Activation uses the same transaction.
Secrets are excluded by default; an explicit secret-bearing export needs supported
cryptographic protection and clear warnings. Keep credentials out of URLs, logs,
status payloads and browser localStorage. Protect state-changing operations with
server authorization and CSRF protection; do not add a new unauthenticated API.

## Minimal interface change

Retain existing equivalents of Dashboard (Status), Wi-Fi/WDS, Network, DHCP,
Firewall, System, Logs, and Backup/Restore. Keep current labels/layout where
possible; add **WDS Profiles** under Wireless, not a replacement dashboard.

```text
Profile Name | SSID | BSSID | Channel | Status | Active | Actions
Connect | Edit | Duplicate | Rename | Delete | Scan/Update
```

Add Create and an enabled toggle. Show saved/enabled state, transaction progress,
observed connection state, last failure and rollback outcome separately. Disable
conflicting controls while switching. Poll a small read-only status response at a
bounded interval while the page is visible, with backoff and a stale-data warning;
no refresh loop that starts scans. Escape all user/network-provided strings. Reuse
stock CSS and plain lightweight JavaScript; no SPA framework or unrelated UI edits.

## Logging and acceptance gates

Bounded RAM log ring: transaction ID, profile ID/revision, monotonic durations,
state transitions, changed setting names (not secret values), driver return/error,
verification failure and rollback outcome. Coalesce persistent logs to limit wear.

Required tests: wrong key, absent peer, stale channel, invalid MAC/SSID/region,
unsupported driver field, same-profile no-op, repeated requests, concurrent edit,
active deletion, driver failure in every state, timeout/late event, browser loss,
full/corrupt store, commit failure, reboot/power loss at every storage boundary,
rollback failure, and backup/restore failure. Test packet forwarding, DHCP lease
continuity, firewall/routing invariants, uptime and unrelated task lifetimes.

Measure same-channel and cross-channel switching separately: first/last good
packets, lost packets, association/auth duration, verification/rollback duration,
local AP-client interruption, peak RAM/CPU and flash writes. Publish measured
worst-case interruption and limitations. Production readiness requires repeated
hardware and soak tests; offline tests cannot establish it.
