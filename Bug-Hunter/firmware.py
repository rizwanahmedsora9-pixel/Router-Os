#!/usr/bin/env python3
"""
Bug Hunter v2 — offline firmware analysis module (zero dependencies)
====================================================================

A binwalk-lite for router firmware images and MTD dumps, stdlib only:

  * container/filesystem magic scan (uImage, TRX, SquashFS, JFFS2, LZMA,
    gzip, ELF, UBI, IMG0/TP-Link WR720N, SEAMA, CFE, ZIP, ...),
  * sliding-window entropy profile (finds encrypted/compressed regions),
  * printable-string extraction + secret/indicator scan,
  * SHA-256 + size + report (TXT/JSON) saved under audits/.

Input is a LOCAL file: an MTD dump from --dump-mtd, a --dump-config
backup, or a vendor .bin. Nothing is uploaded anywhere. Secret VALUES
are never printed — the report shows type + location + redacted preview.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Magic database: (name, pattern, description)
# --------------------------------------------------------------------------- #

MAGIC_DB: List[Tuple[str, bytes, str]] = [
    ("uImage", b"\x27\x05\x19\x56", "U-Boot legacy image header"),
    ("TRX", b"HDR0", "Broadcom TRX firmware container"),
    ("SquashFS-le", b"hsqs", "SquashFS filesystem (little-endian)"),
    ("SquashFS-be", b"sqsh", "SquashFS filesystem (big-endian)"),
    ("SquashFS-4", b"shsq", "SquashFS filesystem (v4, xz)"),
    ("JFFS2-be", b"\x85\x19", "JFFS2 filesystem node (big-endian)"),
    ("JFFS2-le", b"\x19\x85", "JFFS2 filesystem node (little-endian)"),
    ("CramFS", b"Compressed ROMFS", "CramFS filesystem"),
    ("gzip", b"\x1f\x8b\x08", "gzip compressed data"),
    ("LZMA-alone", b"\x5d\x00\x00", "LZMA-alone stream (common dict bits)"),
    ("XZ", b"\xfd7zXZ\x00", "XZ compressed data"),
    ("LZO?", b"\x89LZO", "LZO compressed data"),
    ("ELF", b"\x7fELF", "ELF executable/object"),
    ("UBI", b"UBI#", "UBI volume (NAND flash)"),
    ("UBIFS", b"\x06\x10\x18\x31", "UBIFS superblock"),
    ("IMG0", b"IMG0", "TP-Link IMG0 container (e.g. TL-WR720N V2)"),
    ("WR720N-store", b"\xb1\x1a\xa9\x5f", "Wind River mgmt-fs store magic (WR720N, LE of 0x5FA91AB1)"),
    ("SEAMA", b"SEAMA", "Seama firmware container (D-Link/others)"),
    ("CFE", b"CFE1", "Broadcom CFE bootloader"),
    ("ZIP", b"PK\x03\x04", "ZIP archive"),
    ("JIMAGE", b"JIMAGE", "JFFS2/JIMAGE container"),
    ("QSDK-IPQ", b"MI01", "Qualcomm IPQ APPSBL/partition marker"),
    ("FIT", b"\xd0\x0d\xfe\xed", "Flattened Image Tree (FIT)"),
    ("DTB", b"\xd0\x0d\xfe\xed", "Device-tree blob (same magic as FIT)"),
    ("YAFFS", b"Yaffs", "YAFFS marker string"),
    (" certificates", b"-----BEGIN CERTIFICATE-----", "PEM certificate"),
    ("private-key", b"-----BEGIN RSA PRIVATE KEY-----", "PEM RSA private key"),
    ("private-key-ec", b"-----BEGIN EC PRIVATE KEY-----", "PEM EC private key"),
    ("private-key-openssh", b"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
]


def scan_magics(path: str, max_bytes: int = 64 * 1024 * 1024) -> List[Dict[str, Any]]:
    """Search the file for every known magic. Returns [{name, offset, desc}]."""
    hits: List[Dict[str, Any]] = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return hits
    with open(path, "rb") as fh:
        data = fh.read(min(size, max_bytes))
    for name, pattern, desc in MAGIC_DB:
        start = 0
        count = 0
        while count < 25:  # cap per magic to keep reports readable
            idx = data.find(pattern, start)
            if idx < 0:
                break
            hits.append({"name": name, "offset": idx,
                         "offset_hex": f"0x{idx:X}", "description": desc})
            count += 1
            start = idx + 1
    hits.sort(key=lambda h: h["offset"])
    return hits


# --------------------------------------------------------------------------- #
# Entropy profile
# --------------------------------------------------------------------------- #

def _entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = Counter(block)
    total = len(block)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def entropy_profile(path: str, window: int = 262144,
                    max_windows: int = 128) -> List[Dict[str, Any]]:
    """Sliding-window Shannon entropy. Flags high-entropy (enc/compressed) spans."""
    out: List[Dict[str, Any]] = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return out
    with open(path, "rb") as fh:
        offset = 0
        while offset < size and len(out) < max_windows:
            chunk = fh.read(window)
            if not chunk:
                break
            ent = round(_entropy(chunk), 3)
            flag = ("encrypted/compressed?" if ent >= 7.6 else
                    "compressed?" if ent >= 7.0 else "")
            out.append({"offset": offset, "offset_hex": f"0x{offset:X}",
                        "bytes": len(chunk), "entropy": ent, "flag": flag})
            offset += len(chunk)
    return out


# --------------------------------------------------------------------------- #
# Strings + secret/indicator scan (values redacted in output)
# --------------------------------------------------------------------------- #

def extract_strings(path: str, minlen: int = 5,
                    max_strings: int = 60000,
                    max_bytes: int = 64 * 1024 * 1024) -> List[Tuple[int, str]]:
    """Printable-ASCII runs with file offsets. Streams, low memory."""
    found: List[Tuple[int, str]] = []
    printable = set(range(32, 127)) | {9}
    try:
        size = os.path.getsize(path)
    except OSError:
        return found
    with open(path, "rb") as fh:
        data = fh.read(min(size, max_bytes))
    run = bytearray()
    run_start = 0
    for idx, byte in enumerate(data):
        if byte in printable:
            if not run:
                run_start = idx
            run.append(byte)
        else:
            if len(run) >= minlen:
                try:
                    found.append((run_start, bytes(run).decode("ascii")))
                except UnicodeDecodeError:
                    pass
                if len(found) >= max_strings:
                    return found
            run = bytearray()
    if len(run) >= minlen and len(found) < max_strings:
        found.append((run_start, bytes(run).decode("ascii", "replace")))
    return found


SECRET_RES: List[Tuple[str, re.Pattern, str]] = [
    ("hardcoded-password-assign",
     re.compile(r"(?i)[\w.\-]*?(password|passwd|psk|passphrase|presharedkey)\b\s*[:=]\s*\S+"),
     "looks like a password assignment inside the image"),
    ("default-cred-pair",
     re.compile(r"(?i)\b(admin\s*[:/]\s*admin|root\s*[:/]\s*(root|admin)|"
                r"admin\s*[:/]\s*password|guest\s*[:/]\s*guest)\b"),
     "well-known default credential pair embedded in the image"),
    ("telnet-backdoor-cmd",
     re.compile(r"telnetd\s+(-l\s*\S+|--login\s+\S+)|utelnetd\s+-d"),
     "telnet daemon invocation with a login shell"),
    ("private-key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "private key material inside the image (unique per unit?)"),
    ("aws-key",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "possible AWS access-key ID (usually a vendor/SDK leak)"),
    ("url-hardcoded",
     re.compile(r"https?://[A-Za-z0-9_.\-]{3,60}(?::\d{1,5})?(?:/[A-Za-z0-9_.\-~/?#=&%]{0,80})?"),
     "hardcoded URL (update server? telemetry? check trust)"),
    ("ipv4-hardcoded",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "hardcoded IPv4 address"),
]


def _redact_preview(kind: str, value: str) -> str:
    if kind in ("url-hardcoded", "ipv4-hardcoded"):
        return value[:100]  # indicators, safe to show
    if kind == "aws-key":
        return value[:4] + "…[REDACTED]"
    # password-likes: show the key name only.
    m = re.match(r"(?i)\s*([A-Za-z_.\-]+)\s*[:=]", value)
    if m:
        return f"{m.group(1)}=[REDACTED]"
    return f"{value[:12]}…[REDACTED]"


def scan_indicators(strings: List[Tuple[int, str]],
                    max_hits: int = 300) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for offset, text in strings:
        for kind, rx, note in SECRET_RES:
            for m in rx.finditer(text):
                if kind == "ipv4-hardcoded":
                    # Skip versions (1.2.3.4-style) and netmasks.
                    octets = m.group(0).split(".")
                    try:
                        if not all(0 <= int(o) <= 255 for o in octets):
                            continue
                    except ValueError:
                        continue
                    if m.group(0) in ("0.0.0.0", "255.255.255.0", "255.255.255.255",
                                      "127.0.0.1"):
                        continue
                hits.append({"type": kind, "offset": offset + m.start(),
                             "offset_hex": f"0x{offset + m.start():X}",
                             "preview": _redact_preview(kind, m.group(0)),
                             "note": note})
                if len(hits) >= max_hits:
                    return hits
    return hits


# --------------------------------------------------------------------------- #
# Top-level analysis
# --------------------------------------------------------------------------- #

def sha256_of(path: str) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def analyze_firmware(path: str, outdir: Optional[str] = None,
                     verbose: bool = False) -> Dict[str, Any]:
    """Full offline analysis. Returns report dict; optionally saves TXT+JSON."""
    report: Dict[str, Any] = {
        "tool": "Bug Hunter firmware analysis", "file": path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "size": None, "sha256": None, "magics": [], "entropy": [],
        "string_count": 0, "indicators": [], "summary": [],
        "error": None,
    }
    if not os.path.isfile(path):
        report["error"] = f"file not found: {path}"
        return report
    try:
        report["size"] = os.path.getsize(path)
    except OSError as exc:
        report["error"] = str(exc)
        return report
    report["sha256"] = sha256_of(path)
    if verbose:
        print(f"    [*] {path}: {report['size']} bytes, sha256 {report['sha256'][:16]}…")

    report["magics"] = scan_magics(path)
    if verbose:
        print(f"    [*] magic hits: {len(report['magics'])}")
    report["entropy"] = entropy_profile(path)
    strings = extract_strings(path)
    report["string_count"] = len(strings)
    report["indicators"] = scan_indicators(strings)
    if verbose:
        print(f"    [*] strings: {len(strings)}, indicators: {len(report['indicators'])}")

    # Human summary lines.
    summary = []
    if report["magics"]:
        kinds = sorted({h["name"] for h in report["magics"]})
        summary.append(f"Containers/filesystems seen: {', '.join(kinds)}.")
    else:
        summary.append("No known container/filesystem magic — possibly encrypted, "
                       "obfuscated, or a raw partition.")
    high = [w for w in report["entropy"] if w.get("flag")]
    if high:
        spans = ", ".join(w["offset_hex"] for w in high[:8])
        summary.append(f"High-entropy spans at {spans} (compressed/encrypted regions).")
    by_type: Dict[str, int] = {}
    for hit in report["indicators"]:
        by_type[hit["type"]] = by_type.get(hit["type"], 0) + 1
    if by_type:
        summary.append("Indicators: " + ", ".join(f"{k}×{v}" for k, v in sorted(by_type.items())) + ".")
    else:
        summary.append("No hardcoded secrets/indicators matched.")
    if any(h["type"] in ("private-key", "hardcoded-password-assign",
                         "default-cred-pair", "telnet-backdoor-cmd")
           for h in report["indicators"]):
        summary.append("ATTENTION: the image embeds credential/key material — "
                       "assume every unit ships it until proven per-unit unique.")
    report["summary"] = summary

    if outdir:
        save_firmware_report(report, outdir)
    return report


def render_firmware_text(report: Dict[str, Any]) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("  BUG HUNTER — FIRMWARE ANALYSIS REPORT")
    lines.append("=" * 78)
    lines.append(f"  File      : {report.get('file')}")
    lines.append(f"  Size      : {report.get('size')} bytes")
    lines.append(f"  SHA-256   : {report.get('sha256')}")
    lines.append(f"  Timestamp : {report.get('timestamp')}")
    lines.append("")
    lines.append("  SUMMARY")
    for item in report.get("summary", []):
        lines.append(f"    - {item}")
    lines.append("")
    lines.append("  MAGIC HITS (containers / filesystems / blobs)")
    if report.get("magics"):
        for hit in report["magics"][:60]:
            lines.append(f"    {hit['offset_hex']:>10}  {hit['name']:<16} {hit['description']}")
        if len(report["magics"]) > 60:
            lines.append(f"    ... and {len(report['magics']) - 60} more")
    else:
        lines.append("    (none)")
    lines.append("")
    lines.append("  ENTROPY PROFILE (256 KiB windows)")
    for win in report.get("entropy", [])[:40]:
        flag = f"  <-- {win['flag']}" if win.get("flag") else ""
        lines.append(f"    {win['offset_hex']:>10}  {win['entropy']:.3f}{flag}")
    lines.append("")
    lines.append(f"  INDICATORS ({len(report.get('indicators', []))} shown, values redacted)")
    for hit in report.get("indicators", [])[:120]:
        lines.append(f"    [{hit['type']}] @ {hit['offset_hex']}: {hit['preview']}")
        lines.append(f"        ({hit['note']})")
    lines.append("")
    lines.append("  NOTE: secret values are never printed. Offsets above let you")
    lines.append("  inspect your OWN dump with:  dd if=file bs=1 skip=<dec> count=256 | xxd")
    lines.append("=" * 78)
    return "\n".join(lines)


def save_firmware_report(report: Dict[str, Any], outdir: str) -> Tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(report.get("file") or "firmware"))
    base = os.path.join(outdir, f"fwanalysis_{base_name}_{stamp}")
    txt_path, json_path = base + ".txt", base + ".json"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(render_firmware_text(report))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    try:
        os.chmod(txt_path, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(json_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    report["saved_txt"] = txt_path
    report["saved_json"] = json_path
    return txt_path, json_path
