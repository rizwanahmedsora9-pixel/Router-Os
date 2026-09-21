# tools

## `wr720n_fw.py`

Single-file Python 3 tool (standard library only — just `lzma`). It knows the TP-Link "IMG0"
container, the two compressed VxWorks images and the "Wind River management filesystem" of the
TL-WR720N (EU) V2 image.

```bash
python3 wr720n_fw.py info   <firmware.bin>
python3 wr720n_fw.py unpack <firmware.bin> <out_dir> [--no-images] [--no-web]
python3 wr720n_fw.py verify <firmware.bin>
python3 wr720n_fw.py repack <firmware.bin> <webroot_dir> <out.bin>     # experimental
```

| command | what it does |
|---|---|
| `info` | prints both IMG0 headers, the two LZMA streams (props, dictionary, sizes, ratio, end offsets), and a summary of the store: records, unique files, extension breakdown, orphan streams |
| `unpack` | writes `vxworks-image-1/main-code.bin`, `vxworks-image-2/main-code.bin`, `webroot/` (194 files), `tail-part/part-5632.bin`, `MANIFEST.csv/json`, `img0-headers.txt` |
| `verify` | decompresses **every** file and checks it against its record: stream must end exactly at `offset+20+size`, output length must equal the size in the LZMA header, `.jpg/.gif/.png` must carry their magic bytes, text files must not start with binary |
| `repack` | rebuilds the whole filesystem store from an edited `webroot`: unchanged files keep their **original compressed bytes**, changed files are re-compressed with the vendor's LZMA parameters, the 194 record entries are rewritten so every offset stays consistent, and the store is re-packed 4-byte aligned. Add `--grow` if the store needs more room (the tail part is moved and the five length/offset fields in the two IMG0 headers are patched by the same delta) |
| `repack --grow` | the growing variant; without it the tool **refuses** to build rather than write an inconsistent image |

The full byte-map, record format and the evidence behind it are documented in
[`../unpacked-os/v2.0-160426/README.md`](../unpacked-os/v2.0-160426/README.md).

> ⚠️ `repack` output is for analysis/QEMU. It has not been flashed on hardware, and the
> router's upgrade validation has not been reverse engineered yet.

## Verified behaviour

```
zero-change rebuild : byte-identical to the stock image  (round-trip proof of the format)
one edited file     : Index.htm 576 -> 587 bytes, image +12 bytes, tail part moved,
                      5 header fields patched, `verify` -> OK, the edit survives
unchanged files     : copied verbatim (only the edited stream is re-encoded)
```

LZMA parameters the vendor uses (important if you ever hand-build a stream):

| stream | props byte | lc | lp | pb | dictionary |
|---|---|---|---|---|---|
| the two big images | `0x6E` | 2 | 2 | 2 | 8 MiB |
| every web file | `0x5A` | 0 | 0 | 2 | 8 MiB |

## Reusing it on other TP-Link VxWorks models

The offsets at the top of the file (`IMGHDR_OFFSET_1/2`, `LZMA1_START`, `LZMA2_START`,
`STORE_BASE`, `STORE_SIZE`) are for this model/build. Everything else — the header parser, the
LZMA handling, the 48-byte record walker (which validates itself against real LZMA headers) —
is format generic: `info` + `verify` will report the real values for a sibling model, and the
constants can then be adjusted.
