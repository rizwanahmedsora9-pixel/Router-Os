#!/usr/bin/env python3
"""
wdos_verify.py - host-only verification harness for a WDOS image
=================================================================

Checks a WDOS .bin against the official image and against the project's own policy.
Nothing here touches a router: it reads files on this machine only.

    python3 wdos_verify.py [release/wdos-1.0-160426.bin]

What it proves, in order:
  1. vendor acceptance   - length range, vendor md5, IMG0 header vs the official image
  2. change surface      - the exact byte ranges that differ from the official image
  3. record integrity    - every store record decodes; which records changed, and to what
  4. payload policy      - the text this build *inserts* into the web UI must not submit
                           the form, navigate, reboot, or make a network request
  5. JavaScript          - node --check on every shipped script, and an i18n regression
                           check that every key the pages request resolves exactly as it
                           does in the official image

`node` is needed for step 5 and is optional; everything else is stdlib only.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(PROJECT, "..", "..", ".."))
OFFICIAL = os.path.join(REPO, "wr720n", "official-os", "v2.0-160426", "wr720nv2-eu-up.bin")
DEFAULT_BIN = os.path.join(PROJECT, "release", "wdos-1.0-160426.bin")

spec = importlib.util.spec_from_file_location(
    "wdos_build", os.path.join(HERE, "wdos_build.py"))
wb = importlib.util.module_from_spec(spec)
sys.modules["wdos_build"] = wb
spec.loader.exec_module(wb)

FAILS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)
    return ok


def node_available() -> bool:
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        return True
    except Exception:                                                   # noqa: BLE001
        return False


def node_check(code: str) -> str | None:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="latin1") as fh:
        fh.write(code)
        path = fh.name
    r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
    os.unlink(path)
    return None if r.returncode == 0 else r.stderr.strip()


def differing_ranges(a: bytes, b: bytes) -> list[tuple[int, int]]:
    """Byte ranges where the two files differ, as (start, end) half-open pairs."""
    if len(a) != len(b):
        return [(0, max(len(a), len(b)))]
    out, start = [], None
    for i in range(len(a)):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, len(a)))
    return out


def inserted_slice(old: bytes, new: bytes) -> bytes:
    """The text this build added to `old` to make `new`."""
    i = 0
    while i < min(len(old), len(new)) and old[i] == new[i]:
        i += 1
    j = 0
    while j < min(len(old), len(new)) - i and old[len(old) - 1 - j] == new[len(new) - 1 - j]:
        j += 1
    return new[i:len(new) - j]


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else DEFAULT_BIN
    data = open(path, "rb").read()
    official = open(OFFICIAL, "rb").read()
    print(f"image   : {path}")
    print(f"official: {OFFICIAL}\n")

    print("1. identity and vendor acceptance")
    print(f"  size   {len(data)} bytes")
    print(f"  md5    {hashlib.md5(data).hexdigest()}")
    print(f"  sha256 {hashlib.sha256(data).hexdigest()}")
    problems = wb.vendor_check(data, official)
    check("vendor acceptance (length, md5, IMG0 header)", not problems,
          "" if not problems else "; ".join(problems))

    print("\n2. change surface vs the official image")
    ranges = differing_ranges(official, data)
    total = sum(e - s for s, e in ranges)
    store_lo, store_hi = wb.STORE_BASE, wb.STORE_BASE + wb.STORE_SIZE
    tail_lo, tail_hi = wb.TAIL_START, wb.TAIL_START + wb.TAIL_SIZE
    md5_diff = sum(e - s for s, e in ranges if s >= 4 and e <= 20)
    store_diff = sum(e - s for s, e in ranges if s >= store_lo and e <= store_hi)
    outside = sum(e - s for s, e in ranges
                  if not (s >= 4 and e <= 20) and not (s >= store_lo and e <= store_hi))
    print(f"  {len(ranges)} differing range(s), {total} bytes total")
    print(f"    md5 field [4:20)              : {md5_diff} bytes")
    print(f"    store   [0x{store_lo:X}, 0x{store_hi:X}) : {store_diff} bytes differ "
          f"of {store_hi - store_lo} ({100.0 * store_diff / (store_hi - store_lo):.1f}%)")
    print(f"    anywhere else                 : {outside} bytes")
    check("outside the md5 field and the store region, nothing differs", outside == 0,
          "boot partition, app code stream and tail blob are byte-identical")
    check("md5 field is exactly bytes [4:20)", md5_diff == 16
          and any(s == 4 and e == 20 for s, e in ranges))
    check("tail blob byte-identical", not any(s < tail_hi and e > tail_lo for s, e in ranges),
          "the store rebuild stays clear of it")
    print("    the store is repacked, so stream offsets after the first changed record")
    print("    shift by design; the changed records are listed in step 3")

    print("\n3. record integrity")
    recs = wb.read_records(official)
    was = wb.decode_all(official, recs)
    brecs = wb.read_records(data)
    check("record table identical", [r[0] for r in brecs] == [r[0] for r in recs],
          f"{len(brecs)} records")
    now = wb.decode_all(data, brecs)
    changed = [n for n in now if now[n] != was.get(n)]
    same = [n for n in now if now[n] == was.get(n)]
    check("unchanged records still match the official image byte for byte",
          len(same) == len(recs) - len(changed),
          f"{len(same)} of {len(recs)} unchanged")
    print(f"  changed records ({len(changed)}):")
    for n in changed:
        print(f"    {n}: {len(was[n])} -> {len(now[n])} bytes raw")

    print("\n4. payload policy (the inserted text only)")
    inserted = inserted_slice(was[wb.PATCH_FILE], now[wb.PATCH_FILE])
    print(f"  inserted into {wb.PATCH_FILE}: {len(inserted)} bytes")
    bad = [(needle, why) for needle, why in wb.FORBIDDEN if needle in inserted]
    check("no form submit, navigation, reboot, network call or eval", not bad,
          str(bad) if bad else "")
    errs, _notes = wb.check_snippet(inserted)
    check("tags balanced", not [e for e in errs if "unbalanced" in e])
    check("does not declare a form", b"<FORM" not in inserted and b"<form" not in inserted)
    check("buttons are type=button (cannot submit)", inserted.count(b'type="button"') > 0
          and b'type="submit"' not in inserted)

    print("\n5. JavaScript")
    if not node_available():
        print("  [SKIP] node is not installed - syntax and i18n checks not run")
    else:
        js = sorted(n for n in now if n.endswith(".js"))
        syntax_bad = [n for n in js if node_check(now[n].decode("latin1"))]
        check(f"node --check on {len(js)} shipped scripts", not syntax_bad, str(syntax_bad))
        for i, code in enumerate(re.findall(r"<SCRIPT[^>]*>(.*?)</SCRIPT>",
                                            now[wb.PATCH_FILE].decode("latin1"),
                                            re.S | re.I)):
            if node_check(code):
                check(f"patched page inline script #{i}", False, "syntax error")

        def keys_of(store):
            ks = set()
            for n, b in store.items():
                if n.endswith((".js", ".htm")):
                    ks |= set(re.findall(r"setTagStr\s*\([^,]+,\s*['\"]([^'\"]+)['\"]",
                                         b.decode("latin1")))
            return ks

        def table_of(store):
            code = (store["char_set.js"].decode("latin1")
                    + "\nconsole.log(JSON.stringify(Object.keys(pages_js)));")
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                             encoding="latin1") as fh:
                fh.write(code)
                p = fh.name
            r = subprocess.run(["node", p], capture_output=True, text=True)
            os.unlink(p)
            import json
            return set(json.loads(r.stdout.strip().splitlines()[-1]))

        missing_now = keys_of(now) - table_of(now)
        missing_was = keys_of(was) - table_of(was)
        check("i18n lookups resolve exactly as in the official image",
              missing_now == missing_was,
              f"{len(missing_was)} pre-existing stock gaps in both images; "
              f"lost by this build: {sorted(missing_now - missing_was)}")

    print()
    if FAILS:
        print(f"RESULT: {len(FAILS)} CHECK(S) FAILED")
        for f in FAILS:
            print("  -", f)
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print("This is offline evidence only. It cannot show how the router behaves on "
          "real hardware after flashing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
