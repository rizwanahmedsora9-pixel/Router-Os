# TP-Link TL-WR720N (EU) V2 — firmware workbench

Everything for this router lives under this folder. Three shelves, one tool.

```
wr720n/
├── official-os/            ← what TP-Link shipped (do not edit)
│   ├── TL-WR720N(EU)_V2_160426.zip
│   └── v2.0-160426/
│       ├── wr720nv2-eu-up.bin              1,560,324 bytes  (the firmware)
│       ├── GPL License Terms.pdf
│       └── How to upgrade TP-LINK Wireless  N Router.pdf
│
├── unpacked-os/            ← the firmware, opened up
│   └── v2.0-160426/
│       ├── vxworks-image-1/  ... main-code.bin   636,256 bytes   (boot code + kernel)
│       ├── vxworks-image-2/  ... main-code.bin 3,660,912 bytes   (full VxWorks OS + apps)
│       ├── webroot/          ... 194 web-UI files (htm/js/css/gif/jpg)
│       ├── tail-part/        ... part-5632.bin   5,632 bytes     (opaque config blob)
│       ├── MANIFEST.csv / MANIFEST.json         every file, offset, size, md5
│       └── README.md                            the full byte-map of the .bin
│
├── custom-os/              ← our builds
│   ├── v1/   v2/   v3/     (one folder per experiment, see custom-os/README.md)
│
└── tools/
    └── wr720n_fw.py        info / unpack / verify / repack
```

## Quick start

```bash
cd wr720n

# 1. what is inside the official image?
python3 tools/wr720n_fw.py info   official-os/v2.0-160426/wr720nv2-eu-up.bin

# 2. check every compressed stream is intact (records close exactly)
python3 tools/wr720n_fw.py verify official-os/v2.0-160426/wr720nv2-eu-up.bin

# 3. unpack it (images + 194 web files + manifest)
python3 tools/wr720n_fw.py unpack official-os/v2.0-160426/wr720nv2-eu-up.bin \
                                  unpacked-os/v2.0-160426

# 4. experimental: swap web files and rebuild an image
python3 tools/wr720n_fw.py repack official-os/v2.0-160426/wr720nv2-eu-up.bin \
                                  my-edited-webroot  custom-os/v1/out.bin
```

## The firmware in one paragraph

`wr720nv2-eu-up.bin` is a **TP-Link "IMG0" container** holding **two VxWorks 5.5.1 images**
(one at `0x000000`, one at `0x040080`) that are individually **LZMA** compressed (props `0x6E`,
8 MiB dictionary), followed by the router's **Wind River management filesystem** — a 297,360-byte
store holding the whole web interface: a small header, exactly **194 records** (`name[40]`,
`u32 size`, `u32 offset`) and the back-to-back LZMA streams of every file. A final 5,632-byte
opaque part closes the file. Full details, offsets and the record format are in
[`unpacked-os/v2.0-160426/README.md`](unpacked-os/v2.0-160426/README.md).

## Safety

Flashing a modified image can brick the router. The `repack` mode changes bytes inside the
payload only and does **not** recompute the outer integrity fields — treat its output as
analysis/QEMU material, not as a flashable image, until an experiment proves otherwise.
The stock image is kept byte-identical in `official-os/` so you can always go back.
