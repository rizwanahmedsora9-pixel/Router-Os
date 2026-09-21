# official-os — stock TP-Link firmware (untouched)

This folder holds the firmware exactly as published by TP-Link. **Nothing here is modified.**

## Provenance

* Archive: `TL-WR720N(EU)_V2_160426.zip`
* Build: `160426` → 2016-04-26 (the VxWorks build inside is stamped `Jun 18 2013, 12:19:11`)
* Hardware: TL-WR720N **(EU)** **V2**
  *(the folder `v2.0-160426` = hardware v2.0, firmware build 160426)*
* Origin: TP-Link support download for `TL-WR720N(EU)_V2` (moved here from the repo root —
  byte-identical, see hashes).

## Contents

| file | size | notes |
|---|---:|---|
| `TL-WR720N(EU)_V2_160426.zip` | 1,812,633 | the vendor archive, unmodified |
| `v2.0-160426/wr720nv2-eu-up.bin` | 1,560,324 | the firmware image (web-upload / TFTP) |
| `v2.0-160426/GPL License Terms.pdf` | 112,046 | GPL notice shipped by TP-Link |
| `v2.0-160426/How to upgrade TP-LINK Wireless  N Router.pdf` | 259,952 | vendor upgrade instructions |

## Hashes

```
TL-WR720N(EU)_V2_160426.zip
  md5    9882e1177854b240bc92f08154b7afb0
  sha256 34a9450f45a5f2170bdca24b774072919103d41a3cf0938bc3bf0bb41417956b

v2.0-160426/wr720nv2-eu-up.bin
  md5    c79f88e79f2735995cd91cb2a5bd0a09
  sha256 0289bed287db6fa34346973957f1a4b88b902a300a530aebf3c1831f3a0542be
```

## Notes

* This is a **VxWorks 5.5.1** firmware (Realtek/Atheros-class MIPS SoC), *not* Linux — OpenWrt
  images for this model do **not** apply to this tree and vice versa.
* Uploading any image to the router goes through the web UI *Software Upgrade* page or the
  bootloader/TFTP recovery described in the vendor PDF. Keep this stock image as the rollback.
* The image is analysed and unpacked into [`../unpacked-os/`](../unpacked-os/).
