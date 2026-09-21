# PTCL TP-Link security research

This directory covers TP-Link equipment that is either sold by PTCL or publicly reported
as a PTCL modem. The model boundary matters: a **TD-W8961N/ND** DSL modem, a
**TD-W9970** VDSL modem, and the standalone **TL-WR840N** router do not share one
firmware or one vulnerability surface.

## Scope and confidence

* **PTCL shop / confirmed product association:** PTCL's device shop lists the
  **TL-WR840N** as a TP-Link router. It is a standalone Ethernet router, not proof of a
  PTCL-customized DSL image.
* **PTCL-use evidence:** public user/support evidence identifies **TD-W8951ND** and
  **TD-W8961N/ND** in PTCL installations. This establishes model use, not the firmware
  on every unit.
* **Weak resale evidence:** marketplace listings describe **TD-W9970** as a PTCL VDSL
  router. The model is also present in TP-Link Pakistan's catalogue, but no public PTCL
  firmware image was found.
* **Not this project:** `../wr720n/` is the separate TL-WR720N(EU) V2 VxWorks firmware
  workbench. It must not be used as evidence for a PTCL DSL modem.

The research therefore labels each result **PTCL product association**, **conditional on
exact model/firmware**, **retail/other-ISP only**, or **unassessed**. A model name alone
is not a firmware match.

## Read-only checker

`tools/ptcl_tplink_check.py` is a conservative inventory and exposure checker:

* only private, link-local, or loopback targets are accepted;
* it reads the root page and response headers for model, hardware, firmware, and RomPager
  clues without logging in;
* it sends a `HEAD /rom-0` request to look for an obvious configuration-backup endpoint;
* optional `--probe-rom0` performs a GET to confirm a binary-looking response, but never
  decodes, prints, or saves the returned configuration (which may contain credentials);
* it never sends crafted cookies, DHCP hostnames, ping/traceroute values, command
  injection, configuration imports, or writes; and
* a loopback mock tests both vulnerable and fixed cases.

```bash
cd ptcl-tplink/tools
python3 ptcl_tplink_check.py 192.168.1.1
python3 ptcl_tplink_check.py 192.168.1.1 --probe-rom0
python3 ptcl_tplink_check.py 192.168.1.1 --model TL-WR840N --hardware V6 --firmware V6_260304 --json report.json
python3 ptcl_tplink_check.py 192.168.1.1 --urls
python3 selftest_mock.py --port 8099 &
python3 ptcl_tplink_check.py 127.0.0.1 --port 8099 --probe-rom0
```

A positive `ROM-0` result means that a sensitive configuration backup is exposed; it is
not a license to download or decode someone else's router backup. Rotate credentials and
replace/update the device instead.

Read [`research/findings.md`](research/findings.md) for the evidence and remediation
matrix. [`tools/README.md`](tools/README.md) documents flags, verdicts, and safe test
coverage.
