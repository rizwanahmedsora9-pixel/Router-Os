# unpacked-os / v2.0-160426 — inside `wr720nv2-eu-up.bin`

Everything in this folder was produced from the **stock** image by
`../tools/wr720n_fw.py`. Nothing was edited.

```
v2.0-160426/
├── img0-headers.txt          both "IMG0" headers, every field decoded
├── MANIFEST.csv / .json      all 194 web files: name, stored size, offset, md5
├── vxworks-image-1/          main-code.bin     636,256 bytes   LZMA -> decompressed
│                             info.txt
├── vxworks-image-2/          main-code.bin   3,660,912 bytes   LZMA -> decompressed
│                             info.txt
├── webroot/                  the router web UI, 194 files, 999,820 bytes
└── tail-part/                part-5632.bin      5,632 bytes   (opaque blob)
```

Reproduce with:

```bash
python3 ../../tools/wr720n_fw.py verify ../../official-os/v2.0-160426/wr720nv2-eu-up.bin
python3 ../../tools/wr720n_fw.py unpack ../../official-os/v2.0-160426/wr720nv2-eu-up.bin .
```

---

## 1. The whole file, byte by byte

| range | size | what |
|---|---:|---|
| `0x000000 – 0x000013` | 20 | image #1 prefix (MD5-looking id block `00142fc0 0e3a8cd9 …`) |
| `0x000014 – 0x000093` | 128 | image #1 **IMG0** header (magic at `0x14`) |
| `0x000094 – 0x00068C3` | 26,672 | image #1 boot/metadata table: 3,334 8-byte entries addressing the `0x10000xxx` space (loader segment/relocation map) |
| `0x00068C4 – 0x00068D3` | 16 | pointer table `0x800077E0 800077E8 800077F0 80007800` — the load addresses of the compressed payload |
| `0x00068D4 – 0x0034640` | 187,757 | **LZMA stream #1** → 636,256 bytes (props `0x6E`, dict 8 MiB) |
| `0x0034641 – 0x003FFFF` | ~47 KB | zero padding → the bootloader partition is 256 KiB |
| `0x040000 – 0x04007F` | 128 | image #2 prefix (zeros) |
| `0x040080 – 0x040093` | 20 | image #2 prefix/id block |
| `0x040094 – 0x040113` | 128 | image #2 **IMG0** header (magic at `0x40094`) |
| `0x040114 – 0x132F66` | 994,899 | **LZMA stream #2** → 3,660,912 bytes (the whole VxWorks OS) |
| `0x132F60 – 0x17B8EF` | 297,360 | **Wind River management filesystem** (= `webroot/`) |
| `0x17B8F0 – 0x17CEEF` | 5,632 | final part (`tail-part/part-5632.bin`, opaque) |
| `0x17CEF0 – 0x17CF03` | 20 | padding to the recorded end of file |

Cross-checks that make this layout certain:

* image #2 header field `+0x18` = `0x0013CE70` = 1,298,032 = size of that image **minus** its
  20-byte prefix; `0x40080 + 0x13CE84 = 0x17CF04` = end of file.
* image #2 header `+0x58` = `0x000F2E53` = 994,899 = **exactly** the bytes the second LZMA
  stream consumes.
* image #2 header `+0x60` = `0x00048990` = 297,360 = the size of the filesystem store.
* image #2 header `+0x64/+0x68` = `0x0013B870`/`0x00001600` → `0x40080+0x13B870 = 0x17B8F0`,
  the 5,632-byte tail part.
* The store body (`0x132F60 + 0x48990 = 0x17B8F0`) ends exactly where the tail part begins.

## 2. The two VxWorks images

`binwalk`-style signatures of the original file, for reference:

```
20      0x14      IMG0 (VxWorks) header                  size 1560304
26740   0x6874    VxWorks operating system "5.5.1"        compiled Jun 18 2013, 12:19:11
26836   0x68D4    LZMA data, props 0x6E, dict 8 MiB       uncompressed 636,256
262292  0x40094   IMG0 (VxWorks) header                  size 1298032
262420  0x40114   LZMA data, props 0x6E, dict 8 MiB       uncompressed 3,660,912
1253216 0x131F60  Wind River management filesystem, compressed, 194 files
```

| extracted | md5 |
|---|---|
| `vxworks-image-1/main-code.bin` | `9ca8aa137b7dc5d4774f5f661391fb0d` |
| `vxworks-image-2/main-code.bin` | `055acd0411970ec83ba8b92a22067ddf` |

The images are MIPS (big-endian, `mipsb`, load address `0x80001000`) VxWorks "loadable" images.
Useful strings found inside image 2:

```
VxWorks5.5.1      Jun 18 2013, 12:19:11      Wind River
"Software Platform for MIPS"
"Copyright(C) 2001-2010 by TP-LINK TECHNOLOGIES CO., LTD."
"/userRpm/SoftwareUpgradeRpm.htm"            "WindNet NAT - RTSP ALG v1.0"
"oem_pf_uEnableTftpUpgrade"                  "MUD" (Wind River web management daemon)
```

> **Note:** if you want to disassemble these, load them with a **MIPS big-endian** loader
> (IDA `mipsb` / Binary Ninja `mips32be`) at base `0x80001000`, not as a flat x86 blob.

## 3. The web filesystem (`webroot/`)

The store is a tiny, hand-rolled filesystem:

```
store base              0x132F60,  size 0x48990 = 297,360
  0x00000..0x00014      header   : 5F A9 1A B1 | 00 00 0C 38 | 0 | 0 | 0
  0x00014..0x00040      one deleted record ("owowow…ow", size 194, offset 91596 —
                        its data slot was later reused by char_set.js)
  0x00040 + 48*k        file record k = 0..193  (194 records = 9,312 bytes):
                            char  name[40]      NUL padded (max 37 chars used)
                            u32be size          = length of the LZMA-alone stream
                            u32be offset        = stream position − 20
  0x024A0..0x4898D      the file data: one LZMA-alone stream per record, packed
                        back to back in record order, every stream closing exactly
                        where the next one begins
```

Decompressing file *k* is therefore exactly:

```python
start = 0x132F60 + record.offset + 20
blob  = firmware[start : start + record.size]
data  = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(blob)
# data length == the 8-byte size stored inside the 13-byte LZMA-alone header
```

Verified for **all 194 records**: each stream reaches its end marker (`eof == True`), consumes
exactly `size` bytes, and produces exactly the size announced in its own header — so the
extraction is byte-exact, not best-effort.

### What is inside (194 files, 999,820 bytes uncompressed)

| extension | count | examples |
|---|---:|---|
| `.htm` | 174 | `Index.htm`, `StatusRpm.htm`, `WlanNetworkRpm.htm`, `AccessCtrl*`, `Wzd*` (wizards) |
| `.js` | 6 | `common.js`, `menu.js`, `char_set.js`, `custom.js`, `str_err.js`, `str_menu.js` |
| `.css` | 2 | `css_main.css`, `css_help.css` |
| `.jpg` | 6 | `top_bg.jpg`, `blue.jpg`, `top1_1.jpg`, … (all `FF D8 FF E0`) |
| `.gif` | 6 | `pw.gif`, `plus.gif`, `minus.gif`, … (all `GIF8`) |

Notes:

* `Index.htm` → `<html><title>TP-LINK</title>` and loads `/localiztion/char_set.js`; the UI is
  the classic TP-Link "Rpm" web manager with wizards (`Wzd*`), wizard/help pages and
  `SoftwareUpgradeRpm.htm` (= the firmware upload page this `.bin` feeds).
* `MANIFEST.csv` lists every file with its record index, stored size, offset, table position,
  uncompressed size and md5 — handy when rebuilding the store.
* The image files' magic bytes match their extensions, which independently confirms that the
  `name ↔ data` pairing above is correct.
* One record is a **deleted file** (wiped name + stale pointer): nothing was lost from the
  shipping firmware, it is simply an empty slot whose 194-byte space now holds bytes of
  `char_set.js`.

## 4. `tail-part/part-5632.bin`

The last 5,632 bytes are not LZMA and contain no readable strings — they are a separate image
part (`+0x64/+0x68` in the image #2 header). It is preserved verbatim for completeness and for
any future repacking work.

## 5. Hashes of the extracted artefacts

```
webroot/                         194 files, 999,820 bytes total
vxworks-image-1/main-code.bin    636,256   md5 9ca8aa137b7dc5d4774f5f661391fb0d
vxworks-image-2/main-code.bin  3,660,912   md5 055acd0411970ec83ba8b92a22067ddf
tail-part/part-5632.bin           5,632    md5 d1699542504132a0c0408f680c881f38
```
