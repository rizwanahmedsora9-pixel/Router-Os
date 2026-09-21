# Offline firmware audit — 2026-09-21

## Scope and confidence

Audited local files at commit `fbaa030ac46ce4c6104ca73e1dfb49e9b96226f0`.
The checkout was clean at the initial audit. The user subsequently supplied a
label transcription confirming TL-WR720N(EU) Ver: 2.0 / TE7WR720NV2; see
[HARDWARE-FOLLOWUP.md](HARDWARE-FOLLOWUP.md) for external corroboration and runtime
leads. The user then supplied the complete Status version and a Run-state WDS
observation; see [STATUS-BASELINE.md](STATUS-BASELINE.md) for correlation and the
initial static Save-handler trace. No direct router access, physical board
inspection, boot log, configuration backup, SDK, or driver source is available.
No router was contacted.
This is a complete snapshot of the **available repository evidence**, not a
complete live-router audit. All runtime conclusions below remain explicitly gated.

Paths below are relative to `wr720n/`; `W` means
`unpacked-os/v2.0-160426/webroot/`. Binary offsets are file offsets in the
**decompressed** `vxworks-image-N/main-code.bin`, not callable addresses.

## Hardware and architecture inventory

| Area | Evidence | Conclusion / remaining gap |
|---|---|---|
| Target | Official filename, ZIP, repository documentation | Image targets TL-WR720N (EU) V2 / 160426; user-reported label now confirms model/revision/region. Reported installed version is now 4.19.55 Build 160426 Rel.73431n; see status baseline for binary corroboration (not a flash-byte comparison). |
| Chipset/BSP | Image 2 `0x2c8c34`: `C:/Tornado2.2/target/config/ar9331/ag7240End.c`; `0x2c9d94`: `AR9330: AP121 Board` | Atheros AR933x/AP121 lineage. Mixed AR9330/AR9331 strings are not exact silicon identification. |
| Boot code | Image 1 `0x8ca10`: `VxWorks5.5.1`; `0x8cc74`: AP121 banner; flash/update command strings | Boot-oriented first image; installed bootloader version, partition map and recovery behavior unverified. Do not treat upgrade image as full flash backup. |
| Kernel/OS | Image 2 `0x2ca880`: `VxWorks5.5.1`; two IMG0/LZMA code streams | VxWorks firmware, repository describes MIPS big-endian. No Linux kernel/rootfs or runnable firmware build system found. |
| Wireless | `wlan9331/os/vxWorks` paths; image 2 `0x35d7d8`: `../os/vxWorks/ath_iw_handler.c`; Atheros HAL strings | Vendor VxWorks wireless stack, with ath/802.11 ioctl and HAL references. Exact driver release, ABI, callable entrypoints and capabilities unknown. Do not substitute Linux ath9k tools. |
| Filesystem | Existing tool verifies 194 compressed web records; `tffs` strings in both code images | Packed Wind River management web store. `tffs` is a storage lead, not a proven writable filesystem/API. Tail blob remains opaque. |
| Init/services | `-->starting wireless...`, `usrRebootd`, VxWorks task references | Embedded task startup rather than demonstrated Linux init/systemd. Task dependency/restart boundaries unresolved. |
| Networking | Image 2 `0x2d7bd1`: WindNet NAT FCS 1.1; DHCP/route/firewall web pages | Vendor networking/NAT and management components present; live LAN/bridge/radio mapping unknown. |
| Interfaces/resources | `ag7240End.c`, WLAN/VAP strings, shared wireless form | Ethernet and WLAN support indicated. Port/radio counts, RAM, flash size, free space, erase geometry, VLAN/bridge membership and calibration location need live/board evidence. |
| Build/upgrade | `tools/wr720n_fw.py` repacks existing web records | Not an OS compiler or backend extension loader. Repacker loops original records; dropping a new page into a directory does not automatically add a record or HTTP handler. Outer upgrade validation remains unresolved. |

Evidence is saved in `research/image-1-strings.txt`, `image-2-strings.txt`,
`driver-evidence.txt`, and `firmware-info.txt`. Strings can be unused, shared
across boards, or diagnostic names: they are not proof of reachable APIs.

## Existing WDS and scanning

`W/WlanNetworkRpm.htm`:

- Lines 203–216: `doSurvey()` navigates to `popupSiteSurveyRpm.htm`, passing
  wireless form context. This is a separate user action, not required to fill a peer.
- Line 683: settings form uses GET to `WlanNetworkRpm.htm`. This is a legacy
  management request, not a documented transaction API. Do not replay it as
  an assumed live-switch operation or copy its secret-in-URL pattern.
- Lines 751–796: WDS enable, editable peer SSID/BSSID, Survey and key inputs.
- Lines 800–804: when `wlanPara[13] == 1`, UI says wireless configuration will
  not take effect until reboot. This does not prove every WDS edit requires a
  reboot, but directly rules out promising no-reboot behavior from HTML alone.
- Lines 660–669: extra SSIDs disable WDS in the UI. Staged/multiple-VAP operation
  must not be assumed even though VAP strings exist in the binary.

### Observed fields (not a complete driver schema)

| Setting | Stock field | Initialization / representation |
|---|---|---|
| WDS enabled | `wdsbrl` | `wlanPara[22]`, checkbox value 2 |
| Peer SSID | `brlssid` | `[23]`, displayed maximum 32 |
| Peer BSSID | `brlbssid` | `[24]`, displayed hyphen-separated MAC |
| Channel | `channel` | `[10]`; 0 means Auto in UI |
| Width | `chanWidth` | `[11]`; 1=20 MHz, 2=Auto, 3=40 MHz |
| Wireless mode | `mode` | `[7]`, capability-dependent options |
| Security | `keytype` | `[25]`; 1=None, 2=WEP ASCII, 3=WEP HEX, 4=WPA-PSK/WPA2-PSK |
| Key | `keytext` | `[26]`; sensitive, never log/export by default |
| WEP slot / auth | `wepindex` / `authtype` | `[27]` / `[32]`; slots 1–4; open=1/shared=2 |
| Local AP / broadcast | `ap` / `broadcast` | `[8]` / `[9]`; preserve unless an explicitly supported change requires otherwise |

These array indices belong to this page/build only. Stock validation is not a
safe backend specification. Actual SSID byte encoding, cipher negotiation,
4-address handling, regulatory limits and radio identifiers require inspection.
No arbitrary interface names or region values may be hard-coded in the new system.

`W/popupSiteSurveyRpm.htm` passes survey context back to the wireless page and
uses `refresh` for survey refresh. `siteSurveyPara` is server-supplied. Exact
scan initiation/completion behavior and off-channel impact are unresolved.
Binary leads include `IEEE80211IOCTL_SETSCAN`, `GETSCAN`, and
`apcfg_wlanscanresult_get` (image 2 `0x331384`).

`W/StatusRpm.htm:181,212–224` reads WDS state from `wlanPara[10]`:
0 Init, 1 Scan, 2 Join, 3 Auth, 4 Assoc, 5 Run, 6 Disable; other values Invalid.
This is a different page-specific array. **Run alone is not verification of the
expected peer, authentication, or bridge traffic.** No dedicated live-status API
has been demonstrated.

## Can WDS switch without reboot?

**Not yet established.** Image 2 contains `wlan_set_channel` (`0x312c7c`),
`ar9300ChannelChange` (`0x2f7dac`), `IEEE80211IOCTL_WDS` (`0x330dac`),
`SETAP` (`0x34b91c`) and `SETESSID` (`0x34b940`) diagnostic strings. These are
reverse-engineering leads, not verified callable functions, atomic operations,
or safe ordering. An initial candidate settings Save-path disassembly is now recorded in the
status baseline, but no source-backed ABI, controlled runtime experiment, restart
dependency map, or timings are available.

| Change | Minimum scope to investigate | Proven required restart |
|---|---|---|
| Profile name / enabled flag / duplicate | Profile store only | None by proposed design; backend does not exist yet |
| Peer SSID/BSSID | WDS station/peer context | Unknown |
| Security/key | Peer authentication/key context | Unknown |
| Channel/width/mode | Possibly entire shared radio and its AP clients | Unknown |
| Bridge parameters | WDS port/membership only where supported | Unknown |
| Scan | Radio scan engine; potential off-channel interruption | Unknown |

No permission to restart LAN, DHCP, firewall, routing or the whole network is
implied. If one radio must retune between channels, concurrent old/new service
may be impossible; measure the actual interruption rather than claiming zero.
There is currently **no measured downtime bound**.

## Persistence, backup and recovery gaps

`W/BakNRestoreRpm.htm` downloads `config.bin` and posts restores to
`/incoming/RouterBakCfgUpload.cfg`. We have not downloaded a real backup, decoded
its format, verified restore effects, or tested recovery. Configuration and
calibration flash locations and atomic-write guarantees are unknown.

Existing workbench notes suggest bootloader/TFTP recovery and Malta/QEMU testing.
Neither is established for the user's board by this audit. A generic MIPS Malta
machine is not an AP121 hardware model; a successful container test or generic
emulation cannot establish radio operation or a safe recovery path.

**Decision:** preserve all existing components. Stop before implementation until
[HARDWARE-CHECKLIST.md](HARDWARE-CHECKLIST.md) is satisfied. A UI-only profile list
or browser localStorage would not satisfy router-side persistence, verified live
switching, rollback, or power-loss safety.
