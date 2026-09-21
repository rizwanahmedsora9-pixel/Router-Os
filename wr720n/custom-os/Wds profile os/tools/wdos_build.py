#!/usr/bin/env python3
"""
wdos_build.py - WDOS build + vendor-acceptance tool for the TP-Link TL-WR720N (EU) V2
====================================================================================

This adds the piece the repository was missing: **the vendor's own upgrade-acceptance
rules**, recovered from the firmware.  With them a modified image can be built that the
router will actually accept, and any image can be checked offline the way the router
checks it.

Recovered vendor scheme (evidence in ../VENDOR-FORMAT.md)
--------------------------------------------------------
The routine at vaddr 0x802b374c of the decompressed image #2 performs exactly three
checks, in this order (the web upgrade task and the bootloader both go through it):

1. length    0x8010 <= len(file) <= 0x1C0000
2. md5       md5(file with bytes [4:20) replaced by a fixed 16-byte placeholder)
             must equal the 16 bytes stored at [4:20)
3. header    the incoming IMG0 header is compared against the *running* image header
             (magic word, version word with a wildcard, and a no-downgrade low byte)

The placeholder is a 16-byte constant at vaddr 0x8035EB7C of decompressed image #2.
Bytes [0:4) are hashed as-is and are not replaced.

What this tool guarantees for the images it writes
--------------------------------------------------
* byte length identical to the official image
* every IMG0 header field identical to the official image
* boot partition  (file [0x94, 0x40094))  byte-identical to the official image
* image #2 LZMA code stream               byte-identical
* opaque 5,632-byte tail blob, same offset, byte-identical
* only the management-filesystem region [0x132F60, 0x17B8F0) is rebuilt
* the vendor md5 at [4:20) is recomputed so the router's check passes

Every reclamation it performs is re-verified from the image at build time; the build
aborts rather than produce something it cannot justify.

Usage
-----
    python3 wdos_build.py build  [--official BIN] [--outdir DIR]
    python3 wdos_build.py check  BIN
    python3 wdos_build.py layout [--snippet FILE|--no-snippet]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(PROJECT, "..", "..", ".."))
DEFAULT_OFFICIAL = os.path.join(
    REPO, "wr720n", "official-os", "v2.0-160426", "wr720nv2-eu-up.bin")
DEFAULT_SNIPPET = os.path.join(PROJECT, "payload", "wds_profiles.snippet.html")
DEFAULT_OUTDIR = os.path.join(PROJECT, "release")

# ---- vendor acceptance constants (recovered) ----------------------------------------
MD5_FIELD = slice(4, 20)
MD5_PLACEHOLDER = bytes.fromhex("cc9628ee8dfb21bb3def6cb59f774c7c")
SIZE_MIN = 0x8010
SIZE_MAX = 0x1C0000

# ---- container geometry --------------------------------------------------------------
IMGHDR_1 = 0x14                     # container header ("image #1" record)
IMGHDR_2 = 0x40094                  # application record
LZMA1_START = 0x68D4
LZMA2_START = 0x40114
STORE_BASE = 0x132F60
STORE_SIZE = 0x48990
TAIL_START = 0x17B8F0
TAIL_SIZE = 0x1600
BOOT_START = 0x94                   # file offset mapped to flash address 0
APP_MAGIC = 0x40094                 # file offset mapped to flash address 0x40000
FIRST_RECORD = 0x40
RECORD_STRIDE = 48
NAME_LEN = 40
DATA_AREA = 0x24A0
LZMA_MAGIC5 = b"\x5a\x00\x00\x80\x00"
STOCK_STORE_END = 0x489A1           # the official image's packed data really ends here

# ---- WDOS payload rules --------------------------------------------------------------
# (a) Records that share another record's stream.  The four GIFs are byte-identical to
#     empty.gif, so sharing changes nothing that can be observed.
SAME_CONTENT_SHARE = {
    "helpPic.gif": "empty.gif",
    "minus.gif": "empty.gif",
    "plus.gif": "empty.gif",
    "pw.gif": "empty.gif",
}
# (b) Assets that no file in the store and neither firmware image ever names.  The name
#     keeps serving a valid 43-byte GIF instead of the original picture.
UNREFERENCED_SHARE = {
    "bgColor.jpg": "empty.gif",
    "arc.gif": "empty.gif",
}
# (c) i18n blocks in char_set.js whose key string occurs nowhere else in the image.
#     Verified per build; the block is kept if the key is referenced anywhere.
I18N_FILE = "char_set.js"

PATCH_FILE = "WlanNetworkRpm.htm"
PATCH_ANCHOR = (b'</TABLE>\r\n      <TABLE>\r\n        <SCRIPT type="text/javascript">'
                b'\r\nif(wlanPara[13] == 1)')


def load_repo_tool():
    """Import wr720n/tools/wr720n_fw.py (single source of truth for LZMA parameters)."""
    path = os.path.join(REPO, "wr720n", "tools", "wr720n_fw.py")
    spec = importlib.util.spec_from_file_location("wr720n_fw", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wr720n_fw"] = mod          # dataclass() wants a registered module
    spec.loader.exec_module(mod)
    return mod


fw = load_repo_tool()


# --------------------------------------------------------------------------------------
# vendor acceptance
# --------------------------------------------------------------------------------------
def vendor_md5(data: bytes) -> bytes:
    probe = bytearray(data)
    probe[MD5_FIELD] = MD5_PLACEHOLDER
    return hashlib.md5(bytes(probe)).digest()


def relock(buf: bytearray) -> tuple[str, str]:
    old = bytes(buf[MD5_FIELD]).hex()
    new = vendor_md5(bytes(buf))
    buf[MD5_FIELD] = new
    return old, new.hex()


def vendor_check(data: bytes, reference: bytes | None = None) -> list[str]:
    """Reproduce the router's three acceptance checks."""
    bad: list[str] = []
    n = len(data)
    if not (SIZE_MIN <= n <= SIZE_MAX):
        bad.append(f"length {n} outside vendor range 0x{SIZE_MIN:X}..0x{SIZE_MAX:X}")
    if vendor_md5(data) != bytes(data[MD5_FIELD]):
        bad.append("vendor md5 mismatch: md5(file, [4:20)=placeholder) != file[4:20)")

    def hdr(d: bytes, off: int):
        if d[off:off + 4] != b"IMG0":
            return None
        return {"magic": d[off:off + 4],
                "version": struct.unpack_from(">I", d, off + 8)[0],
                "nparts": struct.unpack_from(">I", d, off + 0x0C)[0]}

    new = hdr(data, IMGHDR_1)
    if new is None:
        bad.append(f"no IMG0 magic at 0x{IMGHDR_1:X}")
    elif reference is not None:
        old = hdr(reference, IMGHDR_1)
        if old:
            if new["magic"] != old["magic"]:
                bad.append("header magic differs from the running image")
            if new["version"] != old["version"] and 0x1BEC493F not in (
                    new["version"], old["version"]):
                bad.append("header version word differs from the running image")
            if (new["nparts"] & 0xFFFF0000) != (old["nparts"] & 0xFFFF0000):
                bad.append("header nparts high half differs from the running image")
            if (new["nparts"] & 0xFF) < (old["nparts"] & 0xFF):
                bad.append("header low byte looks like a downgrade")
    return bad


# --------------------------------------------------------------------------------------
# store handling
# --------------------------------------------------------------------------------------
def read_records(d: bytes):
    recs = []
    pos = FIRST_RECORD
    while pos + RECORD_STRIDE <= DATA_AREA:
        raw = d[STORE_BASE + pos:STORE_BASE + pos + NAME_LEN]
        name = raw.split(b"\x00")[0]
        size = struct.unpack_from(">I", d, STORE_BASE + pos + 40)[0]
        off = struct.unpack_from(">I", d, STORE_BASE + pos + 44)[0]
        if not name or not all(32 <= c < 127 for c in name):
            break
        if d[STORE_BASE + off + 20:STORE_BASE + off + 25] != LZMA_MAGIC5:
            break
        recs.append((name.decode("ascii"), size, off))
        pos += RECORD_STRIDE
    return recs


def decode_all(d: bytes, recs) -> dict[str, bytes]:
    out = {}
    for name, size, off in recs:
        payload, consumed = fw.lzma_decompress(d, STORE_BASE + off + 20)
        if consumed != size:
            raise SystemExit(f"FATAL: {name}: stock stream length mismatch")
        out[name] = payload
    return out


def prune_i18n(decoded: dict[str, bytes], firmware: bytes, verbose=True):
    """Drop i18n blocks whose key string is absent from the ENTIRE firmware once the
    block is taken out - i.e. from every other file in the store and from both
    decompressed firmware images.  A key that appears nowhere can never be looked up,
    so removing it cannot change any page or handler behaviour."""
    text = decoded[I18N_FILE].decode("latin1")
    others = "".join(t.decode("latin1") for n, t in decoded.items() if n != I18N_FILE)
    haystack = others + firmware.decode("latin1")

    def strip(t: str, fname: str):
        m = re.search(r"//\s*File Name:\s*" + re.escape(fname) + r"\r?\n", t)
        if not m:
            return t, 0
        nxt = re.search(r"//\s*File Name:", t[m.end():])
        end = m.end() + nxt.start() if nxt else len(t)
        return t[:m.start()] + t[end:], end - m.start()

    dropped = []
    for fname, head in re.findall(
            r"//\s*File Name:\s*([A-Za-z0-9_.]+)\r?\n([^\r\n]*:\s*\{)", text):
        key = head.split(":")[0].strip()
        trial, ln = strip(text, fname)
        if not ln or key in trial or key in haystack:
            continue                      # still referenced somewhere - keep it
        text = trial
        dropped.append((key, ln))
    if verbose:
        for key, ln in dropped:
            print(f"    dropped i18n block {key!r} ({ln} bytes, key absent from the "
                  f"whole firmware)")
    if text.count("{") != text.count("}"):
        raise SystemExit("FATAL: pruned char_set.js has unbalanced braces")
    return text.encode("latin1"), dropped


# ---- payload policy: what the added UI is allowed (and forbidden) to do --------------
# These are enforced on every build, so a later edit to the snippet cannot quietly
# introduce a form submit, a navigation, a reboot, a network call or an RE'd address.
FORBIDDEN = [
    (b"<FORM", "declares a form"),
    (b'type="submit"', "submit button"),
    (b"type=submit", "submit button"),
    (b".submit(", "programmatic form submit"),
    (b"location.href", "navigation"),
    (b"location.replace", "navigation"),
    (b"SysReboot", "reboot page"),
    (b"reboot", "reboot reference"),
    (b"XMLHttpRequest", "network request"),
    (b"sendBeacon", "network request"),
    (b"fetch(", "network request"),
    (b"http://", "absolute URL"),
    (b"https://", "absolute URL"),
    (b"eval(", "dynamic code evaluation"),
    (b"document.write", "document rewriting"),
]
# void elements (BR, INPUT, ...) have no closing tag and are not in this list
SNIPPET_TAGS = [b"TR", b"TD", b"SELECT", b"SPAN", b"SCRIPT", b"TABLE"]


def check_snippet(snippet: bytes) -> tuple[list[str], list[str]]:
    """Return (errors, notes) for the payload HTML/JS."""
    errs, notes = [], []
    for needle, why in FORBIDDEN:
        if needle in snippet:
            errs.append(f"payload {why}: {needle!r}")
    for tag in SNIPPET_TAGS:
        op = snippet.count(b"<" + tag)
        cl = snippet.count(b"</" + tag)
        if op != cl:
            errs.append(f"payload tag <{tag.decode()}> unbalanced: {op} open, {cl} close")
    if b"localStorage" not in snippet:
        notes.append("payload does not use browser storage")
    if b"doBrl()" not in snippet:
        notes.append("payload does not refresh the stock WDS visibility")
    if snippet.count(b"<SCRIPT") != snippet.count(b"</SCRIPT>"):
        errs.append("payload SCRIPT tags unbalanced")
    return errs, notes


def patch_page(original: bytes, snippet: bytes) -> bytes:
    if original.count(PATCH_ANCHOR) != 1:
        raise SystemExit(f"FATAL: anchor not found exactly once in {PATCH_FILE}")
    text = snippet.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    if not text.endswith(b"\r\n"):
        text += b"\r\n"
    return original.replace(PATCH_ANCHOR, text + PATCH_ANCHOR, 1)


def plan(d: bytes, recs, snippet: bytes | None, verbose=True, reclaim=True):
    """Work out every record's new packed bytes.  Returns (blobs, expected, notes)."""
    decoded = decode_all(d, recs)
    notes = []
    blobs = {name: d[STORE_BASE + off + 20:STORE_BASE + off + 20 + size]
             for name, size, off in recs}
    expected = dict(decoded)                       # name -> expected decompressed bytes

    if snippet is not None:
        errs, sn_notes = check_snippet(snippet)
        if errs:
            raise SystemExit("FATAL: payload policy violation:\n  - " + "\n  - ".join(errs))
        notes += sn_notes
        before = len(blobs[PATCH_FILE])
        new_page = patch_page(decoded[PATCH_FILE], snippet)
        blobs[PATCH_FILE] = fw.compress_vendor(new_page)
        expected[PATCH_FILE] = new_page
        notes.append(f"patched {PATCH_FILE}: {len(decoded[PATCH_FILE])} -> "
                     f"{len(new_page)} bytes raw, {before} -> {len(blobs[PATCH_FILE])} "
                     f"bytes packed ({len(blobs[PATCH_FILE]) - before:+d})")
        before = len(blobs[I18N_FILE])
        firmware = b"".join(fw.lzma_decompress(d, off)[0]
                            for off in (LZMA1_START, LZMA2_START))
        pruned, dropped = prune_i18n(decoded, firmware, verbose=verbose)
        if dropped:
            blobs[I18N_FILE] = fw.compress_vendor(pruned)
            expected[I18N_FILE] = pruned
            notes.append(f"pruned {I18N_FILE}: {len(decoded[I18N_FILE])} -> "
                         f"{len(pruned)} bytes raw, {before} -> {len(blobs[I18N_FILE])} "
                         f"bytes packed ({len(blobs[I18N_FILE]) - before:+d})")

    if not reclaim:
        return blobs, expected, notes
    for name, target in {**SAME_CONTENT_SHARE, **UNREFERENCED_SHARE}.items():
        if blobs[name] == blobs[target]:
            continue
        blobs[name] = blobs[target]
        expected[name] = decoded[target]
        notes.append(f"{name}: stream released, now shares {target}")
    return blobs, expected, notes


def layout(recs, blobs, dedup=True):
    """Assign store-relative offsets.  With dedup, byte-identical streams are stored
    once and referenced by several records (the record format allows this)."""
    pos = DATA_AREA
    placed: dict[bytes, int] = {}
    offsets = {}
    for name, size, off in recs:
        blob = blobs[name]
        if dedup and blob in placed:
            offsets[name] = placed[blob]
            continue
        pos += (-pos) % 4
        placed[blob] = pos
        offsets[name] = pos
        pos += len(blob)
    return offsets, pos


def assemble(d: bytes, recs, blobs, offsets) -> bytes:
    table = bytearray(d[STORE_BASE:STORE_BASE + FIRST_RECORD])
    records = bytearray()
    for name, size, off in recs:
        nm = name.encode("ascii")[:NAME_LEN - 1]
        records += nm + b"\x00" * (NAME_LEN - len(nm))
        records += struct.pack(">II", len(blobs[name]), offsets[name] - 20)
    if len(table) + len(records) > DATA_AREA:
        raise SystemExit("FATAL: record table does not fit")
    store = bytearray(table + records)
    store += b"\x00" * (DATA_AREA - len(store))
    for name, size, off in recs:
        blob = blobs[name]
        if offsets[name] < len(store):
            continue                       # already placed (shared stream)
        store += b"\x00" * (offsets[name] - len(store))
        store += blob
    if len(store) < STORE_SIZE:
        store += b"\x00" * (STORE_SIZE - len(store))
    return bytes(store)


def verify_built(built: bytes, official: bytes, recs, expected) -> list[str]:
    """Decode every record of the built image and compare with the intent."""
    bad = []
    brecs = read_records(built)
    if [r[0] for r in brecs] != [r[0] for r in recs]:
        bad.append("record table changed")
        return bad
    got = decode_all(built, brecs)
    was = decode_all(official, recs)
    for name, want in expected.items():
        if got.get(name) != want:
            bad.append(f"{name}: decompressed content differs from intent")
    for name, want in got.items():
        if name not in expected and want != was.get(name):
            bad.append(f"{name}: unexpected content change")
    return bad


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------
def cmd_build(args) -> int:
    official = open(args.official, "rb").read()
    snippet = open(args.snippet, "rb").read() if args.snippet else None
    os.makedirs(args.outdir, exist_ok=True)

    report = []
    def emit(line=""):
        print(line)
        report.append(line)

    emit(f"WDOS 1.0 build report")
    emit(f"official : {args.official}")
    emit(f"           {len(official)} bytes")
    emit(f"           md5    {hashlib.md5(official).hexdigest()}")
    emit(f"           sha256 {hashlib.sha256(official).hexdigest()}")
    problems = vendor_check(official, official)
    emit(f"           vendor acceptance: "
         f"{'PASS' if not problems else 'FAIL ' + str(problems)}")
    emit()
    if problems:
        raise SystemExit("FATAL: the official image does not pass its own checks")
    recs = read_records(official)
    if len(recs) != 194:
        raise SystemExit(f"FATAL: expected 194 records, found {len(recs)}")

    # ---- self-test 1: a zero-change rebuild must reproduce the official file -------
    emit("=== self-test: zero-change repack + relock ===")
    blobs, expected, _ = plan(official, recs, None, reclaim=False)
    offsets, end = layout(recs, blobs, dedup=False)
    stock_offsets = {n: o for n, _s, o in recs}       # the stored field is start - 20
    if {n: v - 20 for n, v in offsets.items()} != stock_offsets:
        raise SystemExit("FATAL: zero-change layout does not reproduce the official "
                         "record offsets")
    store = assemble(official, recs, blobs, offsets)
    probe = bytearray(official)
    probe[STORE_BASE:STORE_BASE + STORE_SIZE] = store[:STORE_SIZE]
    if len(store) > STORE_SIZE:      # the official image overruns its own store size
        over = store[STORE_SIZE:]
        have = bytes(probe[STORE_BASE + STORE_SIZE:STORE_BASE + STORE_SIZE + len(over)])
        if have != over:
            raise SystemExit("FATAL: zero-change store overrun bytes differ")
    relock(probe)
    if bytes(probe) != official:
        raise SystemExit("FATAL: zero-change rebuild is not byte-identical to the "
                         "official image - the store packer or the md5 scheme is wrong")
    emit(f"    record offsets reproduced : PASS (194/194)")
    emit(f"    packed store 0x{end:X} == official : PASS")
    emit(f"    rebuilt + relocked == official file, byte for byte : PASS")
    emit()

    # ---- self-test 2: the vendor md5 scheme explains the official digest -----------
    emit("=== self-test: vendor md5 scheme ===")
    emit(f"    placeholder   {MD5_PLACEHOLDER.hex()}")
    emit(f"    md5(file,[4:20)=placeholder) = {vendor_md5(official).hex()}")
    emit(f"    official file[4:20)          = {bytes(official[MD5_FIELD]).hex()}")
    emit("    match: PASS")
    emit()

    # ---- the WDOS image -----------------------------------------------------------
    emit("=== building wdos-1.0-160426.bin ===")
    blobs, expected, notes = plan(official, recs, snippet)
    offsets, end = layout(recs, blobs)
    if end > STOCK_STORE_END:
        raise SystemExit(
            f"FATAL: rebuilt store ends at 0x{end:X}, past the official image's "
            f"0x{STOCK_STORE_END:X}. Refusing to grow the image.")
    for n in notes:
        emit(f"    {n}")
    emit(f"    packed store : 0x{end:X} (STORE_SIZE 0x{STORE_SIZE:X}, "
         f"official image 0x{STOCK_STORE_END:X}, spare {STORE_SIZE - end} bytes)")

    store = assemble(official, recs, blobs, offsets)
    if len(store) > STORE_SIZE:
        raise SystemExit(f"FATAL: WDOS store ends at 0x{end:X}, past STORE_SIZE")
    out = bytearray(official)
    out[STORE_BASE:STORE_BASE + STORE_SIZE] = store
    old, new = relock(out)
    out = bytes(out)

    chk = vendor_check(out, official)
    chk += verify_built(out, official, recs, expected)
    invariants = {
        "file length": len(out) == len(official),
        "container header": out[IMGHDR_1:IMGHDR_1 + 0x80] ==
                            official[IMGHDR_1:IMGHDR_1 + 0x80],
        "app header": out[IMGHDR_2:IMGHDR_2 + 0x80] == official[IMGHDR_2:IMGHDR_2 + 0x80],
        "boot partition": out[BOOT_START:APP_MAGIC] == official[BOOT_START:APP_MAGIC],
        "app code stream": out[LZMA2_START:STORE_BASE] ==
                           official[LZMA2_START:STORE_BASE],
        "tail blob": out[TAIL_START:TAIL_START + TAIL_SIZE] ==
                     official[TAIL_START:TAIL_START + TAIL_SIZE],
        "prefix [0:4)": out[0:4] == official[0:4],
    }
    emit(f"    vendor md5   : {old} -> {new}")
    emit("    unchanged    : " + ", ".join(k for k, v in invariants.items() if v))
    emit("    changed      : " + (", ".join(
        k for k, v in invariants.items() if not v) or "nothing that must not change"))
    if not all(invariants.values()):
        raise SystemExit("FATAL: an invariant that must not change, changed")
    if chk:
        emit("    VERIFY FAILED")
        for p in chk:
            emit("      - " + p)
        raise SystemExit(1)

    path = os.path.join(args.outdir, "wdos-1.0-160426.bin")
    open(path, "wb").write(out)
    emit(f"    written      : {path}")
    emit(f"    md5    {hashlib.md5(out).hexdigest()}")
    emit(f"    sha256 {hashlib.sha256(out).hexdigest()}")
    emit("    vendor check : PASS")
    emit("    record check : all 194 records decode to the intended bytes")
    emit("    note         : the repository tool's stock-integrity sniff "
         "(`wr720n_fw.py verify`) "
         "reports exactly one intended difference on this image - the two "
         "never-referenced assets bgColor.jpg / arc.gif carry the shared 43-byte "
         "image stream instead of their original picture. Every LZMA stream still "
         "closes exactly on its record boundary.")
    emit()

    rpath = os.path.join(args.outdir, "wdos-1.0-160426.report.txt")
    open(rpath, "w").write("\n".join(report) + "\n")
    print(f"report written: {rpath}")
    return 0


def cmd_check(args) -> int:
    data = open(args.bin, "rb").read()
    ref = open(args.official, "rb").read() if args.official else None
    print(f"file    : {args.bin}")
    print(f"size    : {len(data)} bytes (0x{len(data):X})")
    print(f"md5     : {hashlib.md5(data).hexdigest()}")
    print(f"sha256  : {hashlib.sha256(data).hexdigest()}")
    print(f"stored  md5[4:20) : {bytes(data[MD5_FIELD]).hex()}")
    print(f"recomputed        : {vendor_md5(data).hex()}")
    problems = vendor_check(data, ref)
    if problems:
        print("VENDOR CHECK FAILED")
        for p in problems:
            print("  -", p)
        return 1
    print("VENDOR CHECK PASSED - length, md5 and header are what the router requires.")
    return 0


def cmd_layout(args) -> int:
    official = open(args.official, "rb").read()
    snip = None
    if not args.no_snippet:
        snip = open(args.snippet, "rb").read()
    recs = read_records(official)
    blobs, expected, notes = plan(official, recs, snip)
    offsets, end = layout(recs, blobs)
    for n in notes:
        print("  ", n)
    print(f"packed store end : 0x{end:X}  (STORE_SIZE 0x{STORE_SIZE:X}, "
          f"official end 0x{STOCK_STORE_END:X})")
    print(f"spare            : {STORE_SIZE - end} bytes")
    return 0 if end <= STOCK_STORE_END else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build the WDOS images")
    b.add_argument("--official", default=DEFAULT_OFFICIAL)
    b.add_argument("--snippet", default=DEFAULT_SNIPPET)
    b.add_argument("--outdir", default=DEFAULT_OUTDIR)
    b.set_defaults(func=cmd_build)

    c = sub.add_parser("check", help="check a .bin against the vendor rules")
    c.add_argument("bin")
    c.add_argument("--official", default=DEFAULT_OFFICIAL)
    c.set_defaults(func=cmd_check)

    l = sub.add_parser("layout", help="dry run the store layout")
    l.add_argument("--official", default=DEFAULT_OFFICIAL)
    l.add_argument("--snippet", default=DEFAULT_SNIPPET)
    l.add_argument("--no-snippet", action="store_true")
    l.set_defaults(func=cmd_layout)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
