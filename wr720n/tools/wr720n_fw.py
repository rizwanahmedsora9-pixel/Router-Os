#!/usr/bin/env python3
"""
wr720n_fw.py - unpack / inspect / repack tool for TP-Link TL-WR720N (EU) V2 firmware
=================================================================================
Firmware file : wr720nv2-eu-up.bin   (TL-WR720N(EU)_V2_160426.zip)
Platform      : TP-Link "IMG0" container  ->  VxWorks 5.5.1 image (MIPS, Atheros-class SoC)
                + "Wind River management filesystem" (the router web UI, 194 files)

DISCOVERED LAYOUT (V2, EU, 2016-04-26 build, 1,560,324 bytes)
-------------------------------------------------------------
0x000000  image #1 record  (20-byte prefix + "IMG0" header at 0x14)
0x000068  ... header fields
0x0068D4  LZMA-alone stream, props 0x6E, dict 0x00800000, usize 636,256
0x034641  end of that stream (partition padded with zeros up to 0x40000)
0x040000  gap / zero padding  (bootloader partition = 256 KiB)
0x040080  image #2 record  (20-byte prefix + "IMG0" header at 0x40094)
0x040114  LZMA-alone stream, props 0x6E, dict 0x00800000, usize 3,660,912
0x132F67  end of that stream  (header field 0x58 = 0x000F2E53 = 994,899 bytes consumed)
0x132F60  image #2 "filesystem store" (base; size 0x48990 = 297,360 from header field 0x60)
            0x0000..0x0014   store header       (20 bytes: magic 0x5FA91AB1, 0x00000C38, ...)
            0x0014..0x003F   ONE DELETED RECORD (name "owowow...ow" 36 bytes wiped,
                                               size 194, offset 91596 -> its data slot
                                               was later reused by top2.jpg)
            0x0040 + 48*k    file record  k = 0..193   (194 records, 9312 bytes):
                                char name[40]      NUL padded
                                u32be size         == length of the LZMA-alone stream
                                u32be offset       == stream position - 20  (store rel.)
            0x24A0           start of the data area; the records are stored back to
                            back in exactly this order, every LZMA stream ends where
                            the next one begins (the store `offset` field is simply
                            `stream_start - 20`, i.e. it points 20 bytes "early").
                            Decompress with  d[STORE_BASE+offset+20 : +size]
0x17B8F0  last part, 0x1600 = 5,632 bytes (opaque; the "factory / config" blob)
0x17CEF0  end of image #2 data; file padded to 1,560,324 bytes (0x17CF04)
-------------------------------------------------------------
Notable: the very first 20 bytes of the .bin (before "IMG0") are an MD5-looking
identifier block (00 14 2f c0 0e 3a 8c d9 ...); it is also repeated at 0x40080.

Usage
-----
    python3 wr720n_fw.py info    <firmware.bin>
    python3 wr720n_fw.py unpack  <firmware.bin> <out_dir> [--no-images] [--no-web]
    python3 wr720n_fw.py verify  <firmware.bin>
    python3 wr720n_fw.py repack  <firmware.bin> <webroot_dir> <out.bin>   [EXPERIMENTAL]

Only the Python standard library is required (lzma).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import lzma
import os
import struct
import sys
from dataclasses import dataclass, asdict, field

# --------------------------------------------------------------------------------------
# constants discovered by analysis
# --------------------------------------------------------------------------------------
IMGHDR_OFFSET_1 = 0x14            # "IMG0" magic of image #1
IMGHDR_OFFSET_2 = 0x40094         # "IMG0" magic of image #2
LZMA1_START = 0x68D4              # main-code LZMA stream of image #1
LZMA2_START = 0x40114             # main-code LZMA stream of image #2
STORE_BASE = 0x132F60             # Wind River management filesystem base
STORE_SIZE = 0x48990              # 297,360 bytes (header field 0x60 of image #2)
TAIL_START = 0x17B8F0             # final 5,632-byte part
TAIL_SIZE = 0x1600
STORE_MAGIC = 0x5FA91AB1
RECORD_STRIDE = 48
NAME_LEN = 40
STORE_HDR_LEN = 0x14              # bytes before the deleted record
FIRST_RECORD = 0x40               # first real record (rel. to store base)
DELETED_REC = 0x14                # the wiped record ("owow...") rel. offset
DELETED_NAME_LEN = 36
DATA_AREA = 0x24A0                # first LZMA stream (rel. to store base)
LZMA_MAGIC5 = b"\x5a\x00\x00\x80\x00"   # props 0x5A + 8 MiB dictionary


# --------------------------------------------------------------------------------------
# data containers
# --------------------------------------------------------------------------------------
@dataclass
class ImgHeader:
    offset: int
    fields: dict = field(default_factory=dict)

    def pprint(self) -> str:
        out = [f"IMG0 header @ 0x{self.offset:06X}"]
        for k, v in self.fields.items():
            if isinstance(v, int):
                out.append(f"  {k:<22} 0x{v:08X}  ({v})")
            else:
                out.append(f"  {k:<22} {v}")
        return "\n".join(out)


@dataclass
class StoreRecord:
    index: int
    name: str
    size: int          # length of the LZMA-alone stream
    offset: int        # relative to STORE_BASE; stream starts at offset + 20
    table_pos: int     # relative position of the name inside the store
    status: str = ""   # "", "deleted", "truncated", "missing"

    @property
    def stream_pos(self) -> int:
        return self.offset + 20


# --------------------------------------------------------------------------------------
# low level helpers
# --------------------------------------------------------------------------------------
def u32be(b: bytes, off: int) -> int:
    return struct.unpack_from(">I", b, off)[0]


def parse_img_header(d: bytes, magic_off: int) -> ImgHeader:
    """Parse the 0x80 bytes of an IMG0 header (magic + fields)."""
    base = magic_off - 0x14                     # start of the 20-byte prefix
    f: dict = {"prefix_md5ish": d[base:base + 0x14].hex()}
    if d[magic_off:magic_off + 4] != b"IMG0":
        raise ValueError("IMG0 magic not found at given offset")
    f["magic"] = "IMG0"
    f["length"] = u32be(d, magic_off + 4)       # payload length
    f["version"] = u32be(d, magic_off + 8)
    f["nparts"] = u32be(d, magic_off + 12)
    f["load_addr"] = u32be(d, magic_off + 16)
    f["flags"] = u32be(d, magic_off + 20)
    f["build"] = d[magic_off + 24:magic_off + 40].replace(b"\x00", b" ").decode("ascii", "replace").strip()
    f["field_0x54"] = u32be(d, magic_off + 0x40)
    for i in range(6):
        f[f"part{i}_off" if i % 2 == 0 else f"part{i}_size_or_off"] = u32be(d, magic_off + 0x44 + 4 * i)
    return ImgHeader(offset=magic_off, fields=f)


def lzma_decompress(d: bytes, start: int, expect_eof: bool = True):
    """Decompress an LZMA-alone stream at `start`; returns (payload, consumed)."""
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    out = dec.decompress(d[start:])
    consumed = len(d) - start - len(dec.unused_data)
    if expect_eof and not dec.eof:
        raise ValueError(f"LZMA stream at 0x{start:X} did not reach its end marker")
    return out, consumed


def lzma_header_info(d: bytes, start: int) -> dict:
    return {
        "props": d[start],
        "dict_size": struct.unpack_from("<I", d, start + 1)[0],
        "uncompressed_size": struct.unpack_from("<Q", d, start + 5)[0],
    }


# --------------------------------------------------------------------------------------
# the Wind River management filesystem ("store")
# --------------------------------------------------------------------------------------
def parse_store(d: bytes) -> tuple[list[StoreRecord], list[int]]:
    """
    Walk the 48-byte records of the store.

    Record frame (48 bytes, in *file* order):
        char  name[40]   NUL padded
        u32be size       == length of the LZMA-alone stream of this file
        u32be offset     == stream position - 20, relative to STORE_BASE

    A record is accepted while its name is printable AND its stream really starts
    with an LZMA-alone header (props 0x5A, 8 MiB dictionary).  The walk stops at
    the data area (0x24A0), which holds the streams themselves.

    Returns (records, orphan_stream_positions)
    """
    base = STORE_BASE
    store_end = base + STORE_SIZE
    records: list[StoreRecord] = []

    # ---- the deleted record that lives in the store header -------------------------
    del_name = d[base + DELETED_REC:base + DELETED_REC + DELETED_NAME_LEN].split(b"\x00")[0]
    del_size = u32be(d, base + DELETED_REC + DELETED_NAME_LEN)
    del_off = u32be(d, base + DELETED_REC + DELETED_NAME_LEN + 4)
    records.append(StoreRecord(index=-1, name=del_name.decode("latin1"),
                               size=del_size, offset=del_off,
                               table_pos=DELETED_REC, status="deleted"))

    # ---- the 48-byte file records --------------------------------------------------
    pos = FIRST_RECORD
    k = 0
    while pos + RECORD_STRIDE <= DATA_AREA:
        raw_name = d[base + pos:base + pos + NAME_LEN]
        name = raw_name.split(b"\x00")[0]
        size = u32be(d, base + pos + NAME_LEN)
        off = u32be(d, base + pos + NAME_LEN + 4)
        printable = bool(name) and all(32 <= c < 127 for c in name)
        sp = base + off + 20
        stream_ok = (off != 0 and off + 20 + size <= STORE_SIZE + 64
                     and d[sp:sp + 5] == LZMA_MAGIC5)
        if not printable or not stream_ok:
            break                      # reached the data area
        records.append(StoreRecord(index=k, name=name.decode("latin1"),
                                   size=size, offset=off, table_pos=pos))
        pos += RECORD_STRIDE
        k += 1

    # ---- streams that no record points at (should not happen) ----------------------
    claimed = {r.stream_pos for r in records if r.status == ""}
    orphans = []
    i = base + DATA_AREA
    while True:
        j = d.find(LZMA_MAGIC5, i, store_end + 64)
        if j < 0:
            break
        if (j - base) not in claimed:
            orphans.append(j - base)
        i = j + 1
    return records, orphans


def extract_web_files(d: bytes, records: list[StoreRecord], out_dir: str,
                      manifest: list[dict]) -> dict:
    """Decompress every valid store record into out_dir. Returns stats."""
    os.makedirs(out_dir, exist_ok=True)
    stats = {"ok": 0, "failed": 0, "deleted": 0, "stale": 0, "bytes": 0}
    for rec in records:
        if rec.status in ("deleted", "stale", "name-overwritten"):
            stats["deleted" if rec.status == "deleted" else "stale"] += 1
            manifest.append({**asdict(rec), "file": "", "decompressed": 0,
                             "md5": "", "note": rec.status})
            continue
        start = STORE_BASE + rec.stream_pos
        try:
            payload, consumed = lzma_decompress(d, start)
        except Exception as exc:                       # noqa: BLE001
            stats["failed"] += 1
            manifest.append({**asdict(rec), "file": "", "decompressed": 0,
                             "md5": "", "note": f"ERROR {exc}"})
            continue
        assert consumed == rec.size, f"{rec.name}: consumed {consumed} != size {rec.size}"
        safe = rec.name.replace("/", "_")
        path = os.path.join(out_dir, safe)
        if os.path.exists(path):
            root, ext = os.path.splitext(safe)
            path = os.path.join(out_dir, f"{root}__{rec.index}{ext}")
        with open(path, "wb") as fh:
            fh.write(payload)
        stats["ok"] += 1
        stats["bytes"] += len(payload)
        manifest.append({**asdict(rec), "file": os.path.relpath(path, out_dir),
                         "decompressed": len(payload),
                         "md5": hashlib.md5(payload).hexdigest(), "note": ""})
    return stats


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------
def cmd_info(path: str) -> int:
    d = open(path, "rb").read()
    print(f"file      : {path}")
    print(f"size      : {len(d)} bytes (0x{len(d):X})")
    print(f"md5       : {hashlib.md5(d).hexdigest()}")
    print(f"sha256    : {hashlib.sha256(d).hexdigest()}\n")

    for off in (IMGHDR_OFFSET_1, IMGHDR_OFFSET_2):
        print(parse_img_header(d, off))
        print()

    print("LZMA main-code streams:")
    for off, label in ((LZMA1_START, "image #1 main code"), (LZMA2_START, "image #2 main code")):
        info = lzma_header_info(d, off)
        _out, consumed = lzma_decompress(d, off)
        print(f"  {label:<20} @0x{off:06X}  props=0x{info['props']:02X} "
              f"dict={info['dict_size']}  usize={info['uncompressed_size']} "
              f"compressed={consumed}  ends@0x{off + consumed:06X}  ratio="
              f"{info['uncompressed_size'] / consumed:.2f}x")

    records, orphans = parse_store(d)
    valid = [r for r in records if r.status == ""]
    print(f"\nWind River management filesystem @0x{STORE_BASE:X} size {STORE_SIZE} "
          f"({STORE_SIZE / 1024:.1f} KiB)")
    print(f"  records          : {len(records)}  (1 deleted, "
          f"{len(records) - 1 - len(valid)} stale/overwritten, {len(valid)} valid)")
    print(f"  unique files     : {len({r.name for r in valid})}")
    print(f"  orphan streams   : {orphans if orphans else 'none'}")
    print(f"  stored bytes     : {sum(r.size for r in valid)}")
    print(f"  longest name     : {max((r.name for r in valid), key=len)!r} "
          f"({max(len(r.name) for r in valid)} chars)")
    exts: dict[str, int] = {}
    for r in valid:
        ext = os.path.splitext(r.name)[1].lower() or "(none)"
        exts[ext] = exts.get(ext, 0) + 1
    print(f"  by extension     : {dict(sorted(exts.items(), key=lambda x: -x[1]))}")

    print("\ntail part  : 0x%X .. 0x%X (%d bytes, opaque blob)" %
          (TAIL_START, TAIL_START + TAIL_SIZE, TAIL_SIZE))
    return 0


def cmd_unpack(path: str, out_dir: str, no_images=False, no_web=False) -> int:
    d = open(path, "rb").read()
    os.makedirs(out_dir, exist_ok=True)

    # ---- metadata docs -------------------------------------------------------------
    with open(os.path.join(out_dir, "img0-headers.txt"), "w") as fh:
        fh.write(parse_img_header(d, IMGHDR_OFFSET_1).pprint() + "\n\n")
        fh.write(parse_img_header(d, IMGHDR_OFFSET_2).pprint() + "\n")

    # ---- the two LZMA images -------------------------------------------------------
    if not no_images:
        for off, sub in ((LZMA1_START, "vxworks-image-1"),
                         (LZMA2_START, "vxworks-image-2")):
            out, consumed = lzma_decompress(d, off)
            folder = os.path.join(out_dir, sub)
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "main-code.bin"), "wb") as fh:
                fh.write(out)
            with open(os.path.join(folder, "info.txt"), "w") as fh:
                fh.write(
                    f"source file      : {os.path.basename(path)}\n"
                    f"compressed at    : 0x{off:X}\n"
                    f"compressed size  : {consumed} bytes (0x{consumed:X})\n"
                    f"uncompressed size: {len(out)} bytes (0x{len(out):X})\n"
                    f"LZMA props       : 0x{d[off]:02X}   dict size: "
                    f"{struct.unpack_from('<I', d, off + 1)[0]}\n"
                    f"md5              : {hashlib.md5(out).hexdigest()}\n"
                    f"sha256           : {hashlib.sha256(out).hexdigest()}\n")
            print(f"[images] {sub}/main-code.bin  {len(out)} bytes")

    # ---- the web filesystem --------------------------------------------------------
    records, orphans = parse_store(d)
    manifest: list[dict] = []
    if not no_web:
        stats = extract_web_files(d, records, os.path.join(out_dir, "webroot"), manifest)
        print(f"[web] {stats['ok']} files, {stats['bytes']} bytes uncompressed "
              f"(deleted={stats['deleted']}, stale={stats['stale']}, failed={stats['failed']})")
        with open(os.path.join(out_dir, "MANIFEST.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(manifest[0].keys()))
            w.writeheader()
            w.writerows(manifest)
        with open(os.path.join(out_dir, "MANIFEST.json"), "w") as fh:
            json.dump(manifest, fh, indent=1)

    # ---- the 5,632-byte tail part ---------------------------------------------------
    tail_dir = os.path.join(out_dir, "tail-part")
    os.makedirs(tail_dir, exist_ok=True)
    with open(os.path.join(tail_dir, "part-5632.bin"), "wb") as fh:
        fh.write(d[TAIL_START:TAIL_START + TAIL_SIZE])
    print(f"[tail] tail-part/part-5632.bin  {TAIL_SIZE} bytes (opaque)")

    if orphans:
        print(f"[warn] {len(orphans)} LZMA stream(s) not referenced by any record: "
              f"{[hex(o) for o in orphans]}", file=sys.stderr)
    return 0


def cmd_verify(path: str) -> int:
    d = open(path, "rb").read()
    problems = []
    records, orphans = parse_store(d)

    # every valid record must decompress to exactly its declared size
    for rec in records:
        if rec.status:
            continue
        start = STORE_BASE + rec.stream_pos
        info = lzma_header_info(d, start)
        try:
            payload, consumed = lzma_decompress(d, start)
        except Exception as exc:                                    # noqa: BLE001
            problems.append(f"{rec.name}: {exc}")
            continue
        if consumed != rec.size:
            problems.append(f"{rec.name}: consumed {consumed} != record size {rec.size}")
        if len(payload) != info["uncompressed_size"]:
            problems.append(f"{rec.name}: payload {len(payload)} != header usize "
                            f"{info['uncompressed_size']}")
        # light content sniffing against the extension
        ext = os.path.splitext(rec.name)[1].lower()
        magic = {
            ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".gif": b"GIF8",
            ".png": b"\x89PNG",
        }.get(ext)
        if magic and not payload.startswith(magic):
            problems.append(f"{rec.name}: content does not start with {magic!r}")
        if ext in (".htm", ".html", ".css", ".js") and b"\x00" in payload[:64]:
            problems.append(f"{rec.name}: text file starts with binary data")

    if orphans:
        problems.append(f"orphan streams: {[hex(o) for o in orphans]}")
    if problems:
        print("VERIFY FAILED")
        for p in problems:
            print("  -", p)
        return 1
    print(f"VERIFY OK - {len([r for r in records if not r.status])} files, all LZMA "
          f"streams close exactly on their record boundaries.")
    return 0


# --------------------------------------------------------------------------------------
# repack: rebuild the filesystem store from an (edited) webroot
# --------------------------------------------------------------------------------------
# props byte 0x5A = (pb*5 + lp)*9 + lc  ->  lc=0, lp=0, pb=2   (the *web files*)
# props byte 0x6E = (pb*5 + lp)*9 + lc  ->  lc=2, lp=2, pb=2   (the two big images)
WP_FILTERS = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 23, "lc": 0, "lp": 0, "pb": 2}]


def compress_vendor(data: bytes) -> bytes:
    """Compress like the vendor does for web files: LZMA-alone, props 0x5A, 8 MiB dict."""
    blob = lzma.compress(data, format=lzma.FORMAT_ALONE,
                         filters=[{**WP_FILTERS[0], "preset": 9 | lzma.PRESET_EXTREME}])
    # rewrite the 13-byte header so it matches the vendor's parameters exactly
    return bytes([0x5A]) + struct.pack("<I", 1 << 23) + struct.pack("<Q", len(data)) + blob[13:]


def cmd_repack(path: str, webroot: str, out_path: str, grow: bool = False) -> int:
    """
    Rebuild the firmware with files taken from `webroot` (same layout as `unpack` output).

    * files you did not change keep their original compressed bytes (copy, not re-encode),
    * changed files are re-compressed with the vendor's LZMA parameters,
    * the 194 record entries (name / size / offset) are written fresh, so every offset stays
      consistent with the new layout,
    * the store keeps its position and, by default, its size: if the new streams do not fit
      the tool stops instead of writing a broken image.

    With ``grow=True`` the store is allowed to grow; the tail part is shifted and the length /
    size fields in both IMG0 headers are adjusted by the same delta.
    """
    d = bytearray(open(path, "rb").read())
    records, _ = parse_store(bytes(d))

    # ---- build the new stream list -------------------------------------------------
    streams: list[tuple[StoreRecord, bytes, str]] = []
    for rec in records:
        if rec.status:
            continue
        orig = bytes(d[STORE_BASE + rec.stream_pos:STORE_BASE + rec.stream_pos + rec.size])
        src = os.path.join(webroot, rec.name)
        if not os.path.isfile(src):
            streams.append((rec, orig, "kept"))
            continue
        new = open(src, "rb").read()
        if new == lzma.decompress(orig):
            streams.append((rec, orig, "kept"))
        else:
            streams.append((rec, compress_vendor(new), "recompressed"))

    # ---- lay the streams out, 4-byte aligned, starting where the vendor starts -----
    pos = DATA_AREA
    layout: list[tuple[StoreRecord, bytes, str, int]] = []
    for rec, blob, status in streams:
        pos += (-pos) % 4
        layout.append((rec, blob, status, pos))
        pos += len(blob)
    used = pos                               # end of the packed data (store-relative)
    stock_used = 0x489A1                     # the stock image itself ends here (+17 over)
    table = bytearray(d[STORE_BASE:STORE_BASE + FIRST_RECORD])       # header + deleted record
    records_blob = bytearray()
    for rec, blob, status, off in layout:
        name = rec.name.encode()[:NAME_LEN - 1]
        records_blob += name + b"\x00" * (NAME_LEN - len(name))
        records_blob += struct.pack(">II", len(blob), off - 20)
    assert len(records_blob) == len(layout) * RECORD_STRIDE
    body = table + records_blob
    store = bytearray(body)
    store.extend(b"\x00" * (layout[0][3] - len(store)))

    delta = max(0, used - STORE_SIZE)
    if used > stock_used:
        extra = used - stock_used
        if not grow:
            changed = [r.name for r, _b, s, _o in layout if s == "recompressed"]
            print(f"ERROR: the rebuilt store needs {extra} byte(s) more than the stock layout "
                  f"allows ({len(changed)} file(s) grew: {', '.join(changed[:5])}"
                  f"{' ...' if len(changed) > 5 else ''}).\n"
                  f"       Either shrink those files or use --grow (moves the tail part and "
                  f"updates the length fields; untested on hardware).")
            return 2
        # grow: make room, move the tail part, patch the header deltas
        payload_delta = used - stock_used
        tail_off = STORE_BASE + STORE_SIZE
        tail = bytes(d[tail_off:tail_off + TAIL_SIZE])
        new_total = len(d) + payload_delta
        d.extend(b"\x00" * payload_delta)                       # room *after* the tail part
        d[tail_off + payload_delta:tail_off + payload_delta + TAIL_SIZE] = tail
        del d[new_total:]                                       # exact new file length
        for off in (IMGHDR_OFFSET_2 + 4,        # image #2 length
                    IMGHDR_OFFSET_2 + 0x4C,     # store size
                    IMGHDR_OFFSET_2 + 0x50,     # tail part offset
                    IMGHDR_OFFSET_1 + 4,        # whole-file length
                    IMGHDR_OFFSET_1 + 0x44):    # end-of-data offset
            struct.pack_into(">I", d, off, u32be(d, off) + payload_delta)
        print(f"note: store grew by {payload_delta} bytes; tail part moved and 5 header "
              f"fields patched.")

    for rec, blob, status, off in layout:
        store.extend(blob)
        store.extend(b"\x00" * ((-(len(store))) % 4))
    fill_to = min(max(used, 0), STORE_SIZE)
    if len(store) < fill_to:
        store.extend(b"\x00" * (fill_to - len(store)))
    d[STORE_BASE:STORE_BASE + len(store)] = store

    with open(out_path, "wb") as fh:
        fh.write(bytes(d))

    changed = [(r.name, r.size, len(b)) for r, b, s, _o in layout if s == "recompressed"]
    print(f"repacked -> {out_path}")
    print(f"  files recompressed : {len(changed)}")
    for name, old, new in changed:
        print(f"    {name:<40} {old:>6} -> {new:>6} bytes")
    print(f"  unchanged files    : {len(layout) - len(changed)} (original bytes kept)")
    print(f"  store used         : {used} / {STORE_SIZE} bytes")
    print("\n!! EXPERIMENTAL: not flashed on hardware.  The router's upgrade validation has\n"
          "   not been reverse engineered - test in QEMU before trusting this image.")
    return 0



def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="print the structure of the firmware")
    p.add_argument("bin")

    p = sub.add_parser("unpack", help="extract images + web filesystem")
    p.add_argument("bin")
    p.add_argument("out_dir")
    p.add_argument("--no-images", action="store_true")
    p.add_argument("--no-web", action="store_true")

    p = sub.add_parser("verify", help="re-check every LZMA stream and record")
    p.add_argument("bin")

    p = sub.add_parser("repack", help="[experimental] rebuild the image from an edited webroot")
    p.add_argument("bin")
    p.add_argument("webroot")
    p.add_argument("out")
    p.add_argument("--grow", action="store_true",
                   help="allow the store to grow (shifts the tail part, patches length fields)")

    args = ap.parse_args(argv)
    if args.cmd == "info":
        return cmd_info(args.bin)
    if args.cmd == "unpack":
        return cmd_unpack(args.bin, args.out_dir, args.no_images, args.no_web)
    if args.cmd == "verify":
        return cmd_verify(args.bin)
    if args.cmd == "repack":
        return cmd_repack(args.bin, args.webroot, args.out, grow=args.grow)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
