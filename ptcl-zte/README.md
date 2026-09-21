# PTCL ZTE security research

This directory is the ZTE counterpart to [`ptcl-dlink/`](../ptcl-dlink/). It is a
model-scoped research note and a **read-only LAN checker** for ZTE DSL/VDSL CPE that
has been associated with PTCL. It is not a claim that every ZTE device on PTCL has the
same firmware.

## What is established

The strongest public match is **ZTE ZXHN H168N v2.2**, including the Pakistan firmware
strings `V2.2.0_PK1.2T5`, `V2.2.0_PK1.2T2`, `V2.2.0_PK11T7`, and `V2.2.0_PK11T4` named
in ZTE's advisory for CVE-2018-7357 and CVE-2018-7358. A public exploit identifies the
`PK1.2T5` build timestamp `20171127193202` and describes an unauthenticated UPnP
WLAN-key disclosure on TCP port `52869`. PTCL ownership is supported by local/community
evidence and by the `PK` firmware naming, not by a current PTCL firmware catalogue.

The H168N also has later ZTE advisories for particular **non-PK** v3.5 variants. Those
are recorded as conditional findings: an exact firmware match is meaningful, but a
foreign ISP suffix is not proof that a PTCL unit runs that build.

## Safety model

`tools/ptcl_zte_check.py`:

* accepts only private, link-local, or loopback addresses;
* reads the web root and extracts model/firmware text without logging in;
* optionally sends exactly one documented, **read-only** `GetSecurityKeys` request to
  the UPnP service; it never sends `SetSecurityKeys`;
* never prints or stores a WLAN key returned by a vulnerable unit; and
* has an offline mock so the positive and negative paths can be tested without a modem.

A `GetSecurityKeys` response is still sensitive because it proves that the device will
return the WLAN secret anonymously. Use `--probe-upnp` only on equipment you own or are
authorized to assess, and treat a positive result as exposure: rotate the Wi-Fi key and
admin password rather than trying to change the key through the checker.

```bash
cd ptcl-zte/tools
python3 ptcl_zte_check.py 192.168.1.1
python3 ptcl_zte_check.py 192.168.1.1 --probe-upnp
python3 ptcl_zte_check.py 192.168.1.1 --json report.json
python3 ptcl_zte_check.py 192.168.1.1 --urls
python3 selftest_mock.py --port 8099 --upnp-port 8100 &
python3 ptcl_zte_check.py 127.0.0.1 --port 8099 --upnp-port 8100 --probe-upnp
```

Read [`research/findings.md`](research/findings.md) for the evidence table, version
boundaries, mitigations, and source links. Tool details and exit codes are in
[`tools/README.md`](tools/README.md).

## Important limitation

Do not flash a retail ZTE image merely because its model name looks similar. Capture the
full model, hardware revision, software version, and PTCL/ISP suffix from the unit, then
ask PTCL or ZTE for the matching image. Firmware families with the same H168N model name
can have different management endpoints and different fixes.
