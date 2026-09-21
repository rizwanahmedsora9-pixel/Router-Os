# Router-Os

A workbench for router firmware: **stock (official) images, fully unpacked trees, and a place
for custom builds and experiments.**

```
Router-Os/
└── wr720n/                        ← TP-Link TL-WR720N (EU) V2
    ├── official-os/               stock vendor firmware, exactly as shipped
    ├── unpacked-os/               the same firmware taken apart (images + web root)
    ├── custom-os/                 our own builds / experiments: v1, v2, v3 …
    └── tools/                     the unpacker / inspector / repacker used for all of it
```

## Start here

| I want to… | go to |
|---|---|
| see the original TP-Link download | [`wr720n/official-os/`](wr720n/official-os/) |
| look at the firmware's insides (kernel image, web UI, file list) | [`wr720n/unpacked-os/`](wr720n/unpacked-os/) |
| build / test my own firmware | [`wr720n/custom-os/`](wr720n/custom-os/) |
| unpack another TP-Link image | [`wr720n/tools/`](wr720n/tools/) |

## What is in this repo today

* **Official:** `TL-WR720N(EU)_V2_160426.zip` → `wr720nv2-eu-up.bin` (1,560,324 bytes,
  build `160426`, i.e. 2016-04-26). MD5 `c79f88e79f2735995cd91cb2a5bd0a09`.
* **Unpacked:** two decompressed VxWorks 5.5.1 MIPS images (636 KB + 3.5 MB) and the complete
  web interface — **194 files** (174 `.htm`, 6 `.js`, 2 `.css`, 6 `.jpg`, 6 `.gif`) — plus a
  machine readable `MANIFEST.csv/json` and the byte-map documentation.
* **Custom:** empty experiment slots `v1`, `v2`, `v3` with a documented workflow and a working
  repack tool (still experimental — see the warnings).

Firmware, its extraction and all notes are documented in
[`wr720n/unpacked-os/v2.0-160426/README.md`](wr720n/unpacked-os/v2.0-160426/README.md).
