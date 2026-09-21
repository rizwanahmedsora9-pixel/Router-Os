# WDOS 1.0 - release

| | |
| --- | --- |
| image | `wdos-1.0-160426.bin` |
| size | 1,560,324 bytes (identical to the official image) |
| md5 | `49fbef1c5a9f2a6deb712c246f4d73bf` |
| sha256 | `9eb112ab0c1e971bbb651e33b2ca2148d079a7c3cd4ec9319fc26bffc2e568d3` |
| built from | `wr720n/official-os/v2.0-160426/wr720nv2-eu-up.bin` (md5 `c79f88e79f2735995cd91cb2a5bd0a09`) |
| report | `wdos-1.0-160426.report.txt` (written by the builder on every build) |

Rebuild it yourself:

```
python3 "wr720n/custom-os/Wds profile os/tools/wdos_build.py" build
python3 "wr720n/custom-os/Wds profile os/tools/wdos_verify.py"
```

`build` is deterministic: rebuilding from the official image produces the same bytes
and the same hashes.

## What it changes

The image is the official 160426 firmware with a **WDS Profiles** row added to the
existing Wireless page, plus the space needed to pay for it. Exactly four of the 194
files in the management filesystem differ; the other 190 decompress byte-for-byte
identically to the official image.

| record | before | after | why |
| --- | --- | --- | --- |
| `WlanNetworkRpm.htm` | 25,507 | 28,654 | the added "WDS Profiles" row + its script |
| `char_set.js` | 91,595 | 85,100 | i18n blocks whose key is referenced nowhere in the firmware |
| `bgColor.jpg` | 634 | 43 | unreferenced asset, stream released to the shared 43-byte image |
| `arc.gif` | 59 | 43 | unreferenced asset, stream released to the shared 43-byte image |

Nothing else moves: file length, both `IMG0` headers, the boot partition
`[0x94, 0x40094)`, the whole application LZMA stream, and the trailing opaque blob are
**byte-identical** to the official image. The only other differing bytes in the entire
file are the 16-byte digest at `[4:20)`, recomputed with the vendor's own scheme (see
[../research/vendor-upgrade-acceptance.md](../research/vendor-upgrade-acceptance.md)).

### The added UI

A `WDS Profiles` row appears with the other WDS fields on the Wireless page, so it is
visible exactly when those fields are (i.e. when WDS is enabled). It offers a picker
plus **Save current** and **Delete**, and it does one thing: fill in the six peer
fields (`brlssid`, `brlbssid`, `keytext`, `keytype`, `wepindex`, `authtype`) that are
already on the page. Presets are stored in **this browser's** `localStorage` only.

* It never submits the form, never navigates, never reboots, and makes no network
  request. `tools/wdos_verify.py` enforces this on every build by scanning the exact
  text the build inserts.
* Applying a preset still means pressing the stock **Save** button, which keeps the
  stock validation, the stock reboot-required warning, and the stock behaviour.
* **The browser copy is convenience only and is never authoritative.** The router's
  configuration is unchanged by saving, loading or deleting a preset; it only changes
  when the stock Save button is used. Clearing the browser's storage loses presets and
  affects nothing on the router.

## Evidence behind the build

Both commands are offline; neither touches a router.

`tools/wdos_build.py build` refuses to write anything unless all of this holds:

1. **Zero-change round trip.** Repacking the store from the official image and
   re-signing it reproduces the official file *byte for byte*, and all 194 record
   offsets match the shipped table. This is what proves the packer and the recovered
   md5 scheme are right, rather than merely plausible.
2. **Vendor acceptance.** Length window, the recovered digest scheme, and the `IMG0`
   header comparison all pass, with the header byte-identical to stock (so no variant
   of the header rule can tell the two images apart).
3. **Invariants.** File length, both headers, the boot partition, the application code
   stream, the trailing blob and `[0:4)` are asserted unchanged; the build aborts
   otherwise.
4. **Record verification.** Every record of the built image is decompressed and
   compared with the intended content.

`tools/wdos_verify.py` adds: the exact change surface (and that **nothing** outside the
store region and `[4:20)` differs), the changed-record list, a payload policy scan of
the inserted text, `node --check` on every shipped script, and an i18n regression check
proving that every key the pages request resolves exactly as it does in the official
image.

The i18n blocks removed from `char_set.js` were chosen mechanically: a block is dropped
only if its key string is absent from every other file in the store *and* from both
decompressed firmware images, so no page, handler or menu can ever look it up.

## What this does NOT prove

Read this before flashing anything.

* **No hardware validation.** No router was contacted and no image was flashed in this
  project. Everything above is file-level evidence.
* **Acceptance is reproduced, not demonstrated.** The build satisfies the rules the
  router's own upgrade path applies to an upload, as recovered by disassembly. That the
  write, the post-write check and the subsequent boot succeed on this specific unit is
  **unverified**.
* **No recovery path is validated here.** Nothing in this repository has been tested
  against a failed boot on this unit.
* **WDS runtime behaviour is untouched and unproven.** This image changes the
  management web UI only. It does not change how WDS connects, and nothing here proves
  a WDS link forms, that a peer is the expected one, or that traffic bridges correctly.
  The fixed channel/width and the stock reboot-required warning are unchanged.
* The vendor's own download page notes that upgrading loses the configuration and that
  this EU build cannot be downgraded. Treat re-flashing the official image as a repair,
  not as a documented rollback, and keep a copy of the official image and the
  configuration backup before doing anything.

If you are not prepared to recover a bricked access point by hand, do not flash this.

## Flashing (stock web UI)

1. Save the official image and a configuration backup somewhere safe; verify the
   official md5 `c79f88e79f2735995cd91cb2a5bd0a09` before you start.
2. System Tools -> Firmware Upgrade, choose `wdos-1.0-160426.bin`, start the upgrade,
   and leave the device powered and connected until it reboots on its own.
3. If the upgrade is refused, stop. A refusal means a vendor check rejected the file -
   do not retry the same file, and do not attempt a workaround.
