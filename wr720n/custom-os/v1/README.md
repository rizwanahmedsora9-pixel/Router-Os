# custom-os / v1 — first experiment

**Goal:** prove the toolchain end to end with the smallest possible change, and learn how the
router reacts to a repacked (not byte-identical) image.

**Status:** ☐ not started   ☐ built   ☐ tested   ☐ works   ☐ failed

## Plan

1. Copy the stock web root: `cp -r ../../unpacked-os/v2.0-160426/webroot webroot`
2. Make one visible, harmless change — e.g. a marker in `Index.htm`:
   `<title>TP-LINK</title>` → `<title>TP-LINK [v1]</title>`
   (a *safer* variant: change nothing at all — a zero-change repack should still produce an
   image that passes `verify`, which proves the round trip).
3. Build:
   ```bash
   cd ../..
   python3 tools/wr720n_fw.py repack \
       official-os/v2.0-160426/wr720nv2-eu-up.bin \
       custom-os/v1/webroot \
       custom-os/v1/wr720nv2-eu-up-v1.bin
   ```
4. Compare and verify:
   ```bash
   cmp -l official-os/v2.0-160426/wr720nv2-eu-up.bin custom-os/v1/wr720nv2-eu-up-v1.bin | wc -l
   python3 tools/wr720n_fw.py verify custom-os/v1/wr720nv2-eu-up-v1.bin
   ```
5. Optional but recommended: boot image #2 under QEMU (`-M malta` class) before touching hardware.

## Build log

| date | what changed | result | md5 of the image |
|---|---|---|---|
| 2026-09-21 | toolchain probe: `Index.htm` title + "[v1 test]" (stream 576 → 587 B) | built with `repack --grow`: image +12 bytes, tail part moved, 5 header fields patched, `verify` OK — **not flashed** | see `wr720nv2-eu-up-v1-probe.bin` |

The probe image (`wr720nv2-eu-up-v1-probe.bin`, md5 in `HASHES` below) exists to prove the build
path end to end, not as a usable firmware. Reproduce it with:

```bash
cp -r ../../unpacked-os/v2.0-160426/webroot webroot
sed -i 's|<title>TP-LINK</title>|<title>TP-LINK [v1 test]</title>|' webroot/Index.htm
cd ../.. && python3 tools/wr720n_fw.py repack \
    official-os/v2.0-160426/wr720nv2-eu-up.bin \
    custom-os/v1/webroot custom-os/v1/wr720nv2-eu-up-v1-probe.bin --grow
python3 tools/wr720n_fw.py verify custom-os/v1/wr720nv2-eu-up-v1-probe.bin
```

## Hashes

```
wr720nv2-eu-up-v1-probe.bin   1560336 bytes   md5 7ef16e015cb44cf542040c64ff6061ba
```

## Notes / open questions

* does the upgrade page (`SoftwareUpgradeRpm.htm`) check an MD5 over the payload?
  → compare the 20-byte id block at `0x00` (and `0x40080`) between a stock and a rebuilt image;
  until we know, assume it is checked.
* keep each new stream inside its original slot — that is what makes the offsets (and therefore
  the whole store) stay valid.
