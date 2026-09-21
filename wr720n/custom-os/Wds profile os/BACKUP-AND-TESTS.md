# Backup, rollback and validation

## Pre-change backup

Created **before adding this directory**, on 2026-09-21:

- Commit: `fbaa030ac46ce4c6104ca73e1dfb49e9b96226f0`
- Branch: `arena/01a0c3c9-router-os`
- Working tree: clean (recorded in `research/git-status-before.txt`).
- External workspace location: `/home/user/router-os-backups/2026-09-21-fbaa030/`
  - `working-tree-before.tar.gz`: complete pre-change tree excluding `.git`.
  - `repository-before.bundle`: complete available Git history/refs, verified with
    `git bundle verify`. Does not include Git credentials/config.
  - `tracked-files.sha256`: every pre-existing tracked file.
  - `backup.sha256`, commit/branch/status and empty pre-change diff.
  - Firmware evidence, fresh extraction and a byte-identical zero-change repack.

Archive and bundle hashes are also saved in `research/backup.sha256`. Large backup
artifacts are deliberately outside Git. They are workspace-local, not an offsite
backup; copy them to a separate trusted location if needed. These are **repository
backups only**, not a router's live configuration or full flash/calibration backup.

## Changed files and rollback

Only `wr720n/custom-os/Wds profile os/` is added. Its contents are documentation
and text evidence. No existing file, web asset, driver, tool or firmware is changed.
No router configuration operation, firmware build with modifications, or flash
operation was performed.

Rollback of this step is simply removal of these new project files after saving
anything you want to keep. Do not reset/overwrite other work or replace `.git`.
For archive recovery, extract into a **separate scratch directory**, verify hashes,
and compare/copy only needed files. Never unpack over a router or the live checkout.
No firmware rollback is needed because nothing was flashed.

## Tests actually run

| Test | Result | Evidence |
|---|---|---|
| Git bundle verification | PASS: complete history, bundle valid | Backup tool output |
| Stock firmware inspection | 1,560,324 bytes, expected IMG0/LZMA layout and 194 valid web files | `research/firmware-info.txt` |
| Existing `verify` tool | PASS: all 194 web streams close on record boundaries | `research/firmware-verify.txt` |
| Fresh unpack vs tracked payloads | PASS: all 197 files byte-identical (194 web, two code images, tail) | `research/extraction-test.txt` |
| Zero-change repack vs official `.bin` | PASS: `cmp` byte-identical | `research/roundtrip-test.txt` |
| Pre-existing tracked-file SHA-256 check | PASS before and after documentation additions | `research/tracked-files.sha256`, `research/final-validation.txt` |
| Documentation scope/links and whitespace | PASS | `research/final-validation.txt` |

The repacker prints `297377 / 297360` bytes for its store accounting; the no-change
output still compares identical to stock. This audit does not resolve that existing
layout/accounting issue or certify modified repacks. There is no new firmware output
in this project.

### Reproduce offline (from repository root)

```sh
python3 wr720n/tools/wr720n_fw.py info wr720n/official-os/v2.0-160426/wr720nv2-eu-up.bin
python3 wr720n/tools/wr720n_fw.py verify wr720n/official-os/v2.0-160426/wr720nv2-eu-up.bin
sha256sum -c 'wr720n/custom-os/Wds profile os/research/tracked-files.sha256'
git diff --check
```

Stock SHA-256:
`0289bed287db6fa34346973957f1a4b88b902a300a530aebf3c1831f3a0542be`.

## Not tested / not claimed

Actual hardware identity, driver ABI, runtime WDS switching, zero/minimal downtime,
rollback, persistence after reboot/power loss, live configuration restore, upgrade
acceptance, resource budget and recovery are all **unverified**. No production
firmware or working profile manager is delivered at this stage. Hardware evidence
is required before implementation, as requested.

## Label follow-up — second audit step (2026-09-21)

Before this step, a second complete tree archive (including the untracked first
stage) and Git bundle were created at:
`/home/user/router-os-backups/2026-09-21-label-followup/`.
All 240 pre-step files were checked against their archive bytes. Bundle validation
passed. Hashes are in `research/label-followup-backup.sha256`; the external backup
also includes `all-files-before.sha256`, status, commit and tracked diff.

Files updated: `README.md`, `AUDIT.md`, `HARDWARE-CHECKLIST.md`, this document.
Files added: `HARDWARE-FOLLOWUP.md`, `research/runtime-leads.txt`,
`research/label-followup-backup.sha256`, `research/label-followup-validation.txt`.
No application/firmware/UI implementation changes. The original research snapshot
and architecture plan remain unchanged. New notes distinguish user-reported label,
secondary model-family references, binary-string leads, and unverified runtime.

Rollback this step by extracting the follow-up archive into a separate directory,
restoring only the four updated Markdown documents and removing only the four
new files listed above. Preserve any subsequent user changes. Do not replace `.git`,
reset the branch, flash a device or restore router configuration for a docs rollback.

Validation results are in `research/label-followup-validation.txt`: original
tracked hashes, update scope against the pre-step archive, local Markdown links,
authored-document whitespace, new string offsets against the original binary,
backup hashes, and stock container verification. No live hardware tests were run.

**Recovery correction:** TP-Link's EU 160426 notes warn against downgrading and
state that configuration is lost on upgrade; merely possessing stock firmware
is not a proven hardware rollback method. See the cited vendor evidence in
[HARDWARE-FOLLOWUP.md](HARDWARE-FOLLOWUP.md). Repository rollback is unaffected.

## Status-version follow-up — third audit step (2026-09-21)

Pre-change backup: `/home/user/router-os-backups/2026-09-21-status-followup/`.
The complete source tree archive was checked against all 244 pre-step files,
including earlier untracked project documentation. Git bundle validation passed.
Archive/bundle hashes are retained in `research/status-followup-backup.sha256`;
`all-files-before.sha256`, status and bundle verification are in the external backup.

Updated files: `README.md`, `AUDIT.md`, `HARDWARE-CHECKLIST.md`,
`HARDWARE-FOLLOWUP.md`, and this document.
Added files: `STATUS-BASELINE.md`, `research/status-static-trace.txt`,
`research/status-followup-backup.sha256`, `research/status-followup-validation.txt`.
The architecture, original binaries, original extracted UI and tooling are unchanged.
No router was contacted or modified. Capstone 5.0.7 was installed in a host-only
external analysis directory; no new runtime dependency was added to the repository.

Rollback: extract this step's backup into a separate scratch directory, restore
only the five updated Markdown files and remove only the four listed additions,
while preserving subsequent work. No branch reset, `.git` replacement, firmware
flash or router Restore is appropriate for this documentation-only change.

Validation recorded in `research/status-followup-validation.txt`: all original
tracked hashes, current-step change scope, links/whitespace, firmware verification,
backup hashes, raw disassembly words and bounded-range coverage, string/header
correlation and release-time arithmetic. Static decoding is not proof of reachable
runtime paths or successful switching. Hardware apply/rollback tests remain pending.
