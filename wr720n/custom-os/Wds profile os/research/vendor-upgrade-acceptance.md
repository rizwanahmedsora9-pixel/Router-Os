# Vendor upgrade-acceptance scheme (recovered)

Host-side, read-only analysis of the official image
`wr720n/official-os/v2.0-160426/wr720nv2-eu-up.bin` (md5
`c79f88e79f2735995cd91cb2a5bd0a09`, 1,560,324 bytes). Nothing here was run on a
router, and no router was contacted. This document records why a modified image can be
made to pass the same check the stock firmware applies to an upload.

All file offsets below are offsets into the *decompressed* image #2
(`wr720n/unpacked-os/v2.0-160426/vxworks-image-2/main-code.bin`, 3,660,912 bytes).
VxWorks text base is `0x80001000`, so `vaddr = file offset + 0x80001000`.

## The three checks

The validation routine lives at vaddr `0x802b374c` (file offset `0x2b274c`). It is
reached from the web upgrade handler for `/userRpm/SoftwareUpgradeRpm.htm`, and the
same message strings appear in the recovery image #1, so the bootloader and the web
handler apply the same rules. Each check has its own failure message:

| check | message string | string at | code that loads it |
| --- | --- | --- | --- |
| length | `The file's length is bad: %d` | `0x2e8820` | `0x2b2784` |
| md5 | `md5 checksum is not correct!` | `0x2e8840` | `0x2b27f4` |
| version/header | `tftp: firmware version check failed` | `0x2e8860` | `0x2b2818` |

Related handler strings: `/userRpm/SoftwareUpgradeRpm.htm` at `0x2e616c` and
`0x2e88b8`, `/userRpm/httpFirmwareUpdateTemp.htm` at `0x2e6200` / `0x2e8888`,
`/incoming/Firmware.htm` at `0x2e61e8`, `the upload file`s name is too long!` at
`0x2e88d8`, `filename` at `0x2e61a8`, `updateInf` at `0x2e61bc`.

Image #1 carries the same validation messages (`0x8c93c`, `0x8c95c`, `0x8c97c`) next
to `MD5 digest of received data:` (`0x8bf78`) and the boot banner
`VxWorks5.5.1` / `Jun 18 2013, 12:19:09` / `AR9330: AP121 Board`
(`0x8ca10`, `0x8ca20`, `0x8cc74`).

## 1. Length

The image length must be inside the accepted window (`0x8010` .. `0x1C0000`). The
official image and any image built by this project are 1,560,324 bytes, far inside it.
This check is not a constraint on the build.

## 2. The digest - verified

The value stored at file bytes `[4:20)` is not `md5(file)` and not `md5(file[0x14:])`.
It **is** reproducible:

```
placeholder = image[0x35DB7C : 0x35DB7C+16]        # vaddr 0x8035EB7C, image #2
value       = cc9628ee8dfb21bb3def6cb59f774c7c

probe = bytearray(file)
probe[4:20] = placeholder
md5(probe) == file[4:20]        # -> True for the official image
```

For the official image this yields `0e3a8cd99ddeffae9ae3dc2399dc4bda`, byte-for-byte
equal to the digest stored in `[4:20)`. Bytes `[0:4)` are hashed as they are; they are
**not** replaced. Re-signing a modified image is therefore:

```
image[4:20] = placeholder
image[4:20] = md5(image)        # digest of the whole file, prefix included
```

The md5 implementation backing this is at vaddr `0x80277f9c` with its IV at
`0x80278024`; the upgrade path fetches the placeholder through the helper at
`0x80009e08`, and the header check it calls is at `0x8000cf48`.

Why the vendor burns a 16-byte sentinel into every image and then replaces it is not
fully understood, and does not need to be: the recipe above reproduces the shipped
digest exactly, which is the only thing the router compares.

## 3. Header comparison

The header check at `0x8000cf48` compares the incoming `IMG0` header against the
*running* image: the magic word, the version word (with `0x1BEC493F` treated as a
wildcard), the high half of the `nparts` field, and a low byte that must not decrease
(no downgrade). This part is the least independently verified piece of the three, and
it does not matter for this project's image: **the WDOS build keeps every header byte
identical to the official image**, so no variant of the header rule can distinguish it
from the image the router already runs.

## Container arithmetic (verified)

* `0x14 + image[0x1C:0x20] == end of file` for image #1's record.
* Image #2's record at `0x40094`: `part0 + 141 == part1`,
  `part1 + part2 == part3`, `part3 + part4 == length`, and
  `0x40094 + length == end of file`.
* The 20-byte prefix in front of image #2 (`0x40080`) is all zeroes, unlike the
  populated prefix at `0x00`.
* The official management-filesystem stream ends 17 bytes past its own declared
  `STORE_SIZE`, i.e. inside the first 17 bytes of the trailing blob. That is a
  pre-existing property of the shipped image, not something this project introduced or
  relies on.

## What this does and does not establish

Establishes: an image can be produced that satisfies the same length, digest and
header rules the router applies to an upload, with every header byte and the entire
boot partition, application code stream and trailing blob copied from the official
release.

Does not establish: that the router's flash write, verification-after-write, or
post-upgrade boot succeeds on this particular unit; that recovery works if it does
not; or anything about WDS behaviour at runtime. Those need hardware, and this project
has deliberately not touched any.
