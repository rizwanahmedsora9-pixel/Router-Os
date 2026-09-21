# custom-os — our own builds and experiments

One folder per attempt: `v1/`, `v2/`, `v3/` … Each folder holds the changed web files, the
rebuilt image, and a short `README.md` describing what was tried and what happened. When an
experiment is abandoned, keep the folder and mark it *failed* — the next attempt starts from
whatever we learned.

```
custom-os/
├── v1/   first experiment  (see v1/README.md)
├── v2/   second experiment (see v2/README.md)
└── v3/   third experiment  (see v3/README.md)
```

## The workflow

```bash
cd wr720n

# 1. copy the stock web root - never edit the unpacked tree directly
cp -r unpacked-os/v2.0-160426/webroot custom-os/v1/webroot

# 2. edit your files
$EDITOR custom-os/v1/webroot/Index.htm

# 3. rebuild an image from the stock one + your webroot
python3 tools/wr720n_fw.py repack \
        official-os/v2.0-160426/wr720nv2-eu-up.bin \
        custom-os/v1/webroot \
        custom-os/v1/wr720nv2-eu-up-v1.bin

# 4. prove the result is still structurally sound
python3 tools/wr720n_fw.py info   custom-os/v1/wr720nv2-eu-up-v1.bin
python3 tools/wr720n_fw.py verify custom-os/v1/wr720nv2-eu-up-v1.bin
```

Files you do not touch keep their **original, byte-identical** compressed stream, so the only
bytes that change are the ones you actually edited. Check that with `cmp -l` between the stock
image and your build — a diff that is larger than expected means something else moved.

## What repack does and does not do

| does | does not |
|---|---|
| rebuilds the record table, so every offset/size stays consistent with the new layout | recompute the outer image integrity fields (the 20-byte id block / `0x5A041337`-style fields) |
| re-compresses changed files with the vendor's parameters (props `0x5A`, `lc=0 lp=0 pb=2`, 8 MiB dict) | prove the router's upgrade code accepts a repacked image |
| leaves unchanged files **byte-identical** (their streams are copied, not re-encoded) | climb over the 5,632-byte tail part without `--grow` |
| reproduces the stock image byte-for-byte when nothing changed | produce something that has been tested on real hardware |

If your edit makes the store bigger than the stock layout, `repack` stops and tells you which
file grew. Re-run with `--grow` (moves the tail part, patches the length/offset fields in both
headers) or shrink the edit.

> ⚠️ **A repacked image has not been validated by the router's upgrade code.** Treat it as
> analysis/QEMU material only. If you do want to flash an experiment: flash over a cable, keep
> the stock image at hand, and remember that this platform recovers through the bootloader/TFTP
> procedure described in `official-os/v2.0-160426/How to upgrade TP-LINK Wireless  N Router.pdf`.

## Rules of the house

1. `official-os/` is **read-only** — the stock image is the rollback baseline.
2. `unpacked-os/` is regenerated, never edited.
3. Every build records what changed, how it was built, and the md5 of the result.
4. Nothing gets flashed until it passes `verify` and, if possible, a QEMU boot test.
