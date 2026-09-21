# custom-os / v3 — deep changes (layout rebuild, kernel/app work)

**Goal:** change things the fixed-slot repack cannot: files bigger than their slots, new files,
extra pages, or patched code inside the VxWorks images.

**Status:** ☐ not started   ☐ built   ☐ tested   ☐ works   ☐ failed

## What has to be implemented / understood first

1. ~~**Store rebuild**~~ — **already implemented** in `wr720n_fw.py repack` (and `--grow`
   moves the tail part + patches the five header fields). The format is documented in
   [`../../unpacked-os/v2.0-160426/README.md`](../../unpacked-os/v2.0-160426/README.md).
2. **Integrity fields** — work out what the router's upgrade code validates:
   * the 20-byte id block at `0x000000` / `0x040080`,
   * field `+0x24 = 0x5A041337` (same in both images),
   * and whether anything has to be recomputed after a rebuild.
   Approach: build two images that differ only in a *known* way and diff every header field.
3. **Code patching** — the two VxWorks images are plain (uncompressed, LZMA-decoded) MIPS
   big-endian code at base `0x80001000`. Patches there mean re-compressing the whole image and
   updating the header fields from point 1.
4. **Test path** — QEMU first, hardware last, stock image kept as rollback.

## Build log

| date | change | result | md5 of the image |
|---|---|---|---|
| | | | |

## Scratch notes

* LZMA parameters used by the vendor: `props 0x6E` = `lc=2 lp=2 pb=2` for the two big
  images, `props 0x5A` = `lc=0 lp=0 pb=2` for the individual web files (8 MiB dictionary in
  both cases).
* The store `offset` field equals `stream_start - 20`, the `size` field equals the exact length
  of the LZMA-alone stream. Both must be recomputed together if the store is rebuilt.
