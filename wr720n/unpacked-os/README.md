# unpacked-os — the firmware, opened up

One folder per firmware version. Everything here is **derived** from
[`../official-os/`](../official-os/) by [`../tools/wr720n_fw.py`](../tools/) — nothing is edited
by hand, so it can always be regenerated and diffed.

```
unpacked-os/
└── v2.0-160426/          ← from TL-WR720N(EU)_V2_160426.zip
    ├── README.md            the complete byte-map + how everything was verified
    ├── img0-headers.txt     decoded IMG0 headers
    ├── MANIFEST.csv/.json   194 web files (name, size, offset, md5)
    ├── vxworks-image-1/     decompressed image #1  (636,256 bytes)
    ├── vxworks-image-2/     decompressed image #2  (3,660,912 bytes)
    ├── webroot/             the web UI as real files (194 files)
    └── tail-part/           the last 5,632-byte image part
```

## What the extraction guarantees

* both VxWorks images decompress **exactly** to the size announced in their own LZMA header
  (636,256 and 3,660,912 bytes), with the end-of-stream marker reached;
* all **194** web files were recovered — each LZMA stream consumes exactly the number of bytes
  its filesystem record declares and ends exactly where the next record starts;
* file names come from the filesystem's own directory records, and the recovered bytes match
  the extensions (every `.jpg` starts with `FF D8 FF E0`, every `.gif` with `GIF8`, the `.css`
  files contain CSS, the `.js` files contain JavaScript) — a built-in proof that no file was
  shifted by a record;
* `verify` re-checks all of the above and passes:

```
$ python3 tools/wr720n_fw.py verify official-os/v2.0-160426/wr720nv2-eu-up.bin
VERIFY OK - 194 files, all LZMA streams close exactly on their record boundaries.
```

## Versioning convention

`<hardware version>-<build date>` — e.g. `v2.0-160426` = hardware **v2.0**, vendor build
**160426** (2016-04-26). When a newer official image is added, unpack it into a sibling folder
(`v2.0-<build>/`) and keep the tool output in the same shape so the two can be diffed:

```bash
diff -r unpacked-os/v2.0-160426/webroot unpacked-os/v2.0-<newbuild>/webroot
```
