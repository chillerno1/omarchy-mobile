# omamobile-device-ingot

Omarchy Mobile's userspace package for the Solana Mobile Saga (codename ingot, SM8475). It hides the Android partitions from desktop tools, holds the USB link to the host, keeps a short power press from powering the phone off, and, from 0.1.4, carries what the bring-up system had installed by hand (and, from 0.1.5, sound): the tool that installs the phone's own firmware from its `modem_a` partition, the ADSP start, a stable Bluetooth address, and the Wi-Fi and camera policy.

| Path | Installs to | What it does |
| --- | --- | --- |
| `vendor/udev/rules.d/10-omamobile-storage.rules` | `/usr/lib/udev/rules.d` | Hides `sda`, `sde` and every Android partition except `userdata` from desktop tools, over all eight of the Saga's LUNs (`sda` to `sdh`). `sda` (the main LUN) and, from 0.1.4, `sde` (slot A's boot LUN, which a later initramfs leaves writable at the disk level so three boot partitions can be updated) get whole-disk nodes no user or desktop tool can open; the read-only flags stay the guard |
| `vendor/udev/rules.d/70-omamobile-dma-heap.rules` | `/usr/lib/udev/rules.d` | The video group and the seat's user get the DMA-BUF heaps, which libcamera's software ISP allocates from |
| `ucm2/conf.d/sm8475/SM8475-Solana-Saga.conf`, `ucm2/Solana/ingot/HiFi.conf` | `/usr/share/alsa/ucm2` | From 0.1.5, the sound card's ALSA use-case profile (card driver `sm8475`, long name `SM8475-Solana-Saga`): the two WSA883x amplifiers as `Speaker` (stereo) or one alone as `Earpiece`, and the two digital microphones as `Mic` (only on a kernel whose device tree puts the VA macro in the card), on `hw:CARD,1` and `hw:CARD,2`. PipeWire picks it up by itself. See "Sound" below |
| (made by `install`) | `/usr/lib/firmware/updates/qcom/sm8475/SM8475-Solana-Saga-tplg.bin` | A link to `linux-firmware-qcom`'s SM8450 HDK topology, under the name the kernel asks for (`qcom/sm8475/<card model>-tplg.bin`). The HDK's graph (two playback and two capture front ends, the WSA, RX and TX back ends) covers this phone |
| `vendor/udev/rules.d/71-omamobile-soundwire.rules` | `/usr/lib/udev/rules.d` | Holds runtime power management on for the three audio SoundWire buses, from their `add` event, so their clocks never stop. Without it the amplifiers leave their bus at its first clock stop and the speaker is silent until a reboot. A workaround, see "Sound" |
| `vendor/udev/rules.d/80-omamobile-bt-addr.rules` | `/usr/lib/udev/rules.d` | Starts `omamobile-bt-addr@hciN.service` when the WCN6855's Bluetooth controller (`hci_uart_qca`) appears |
| `vendor/systemd/system/omamobile-bt-addr@.service`, `bin/omamobile-bt-addr` | `/usr/lib/systemd/system`, `/usr/bin` | The bootloader gives our device tree no Bluetooth address, so the controller registers unconfigured and stays off. Before `bluetooth.service`, this gives it a stable, locally administered, unicast address made on the phone from `/etc/machine-id` (`btmgmt public-addr`, the way to configure an unconfigured controller). Never stored or printed; a controller that comes up configured is left alone |
| `vendor/systemd/system/omamobile-adsp.service`, `bin/omamobile-adsp-start` | `/usr/lib/systemd/system`, `/usr/bin` | Starts the ADSP (battery through `qcom_battmgr` over `pmic_glink`, charging, audio) once the root file system is mounted, since its firmware is on the root and not in the initramfs: writes `start` to the remoteproc whose firmware is `qcom/sm8475/osom/ingot/adsp.mdt` if it is offline. Never stops or restarts it; a running or crashed ADSP is left alone. Inert until that firmware exists (`ConditionPathExists`); a hang marker (`/var/lib/omamobile/adsp-start-pending`) makes the boot after a hung start skip it |
| `vendor/systemd/system/multi-user.target.wants/omamobile-adsp.service` | `/usr/lib/systemd/system/multi-user.target.wants` | The vendor wants link that enables the ADSP unit, as cheetah's boot-time units are enabled. `systemctl mask omamobile-adsp` keeps it off (`disable` doesn't remove a vendor link) |
| `vendor/modprobe.d/omamobile-wifi.conf` | `/usr/lib/modprobe.d` | The three ath11k debug options the mobile WCN6855 firmware needs for now, each with its reason: `dbg_wcn_cbc=1` (the vendor-style cold boot calibration), `dbg_skip_wmm=1` (no WMM parameters), `dbg_no_p2p=1` (no P2P interface). They exist only on the `omamobile-ingot` kernel branch; another kernel logs "unknown parameter" and ignores them. MSIs on the controller's own block is a device tree change, not an option |
| `vendor/NetworkManager/conf.d/20-omamobile-wifi-mac.conf` | `/usr/lib/NetworkManager/conf.d` | The chip reports no permanent MAC, so ath11k makes one up at each load; Wi-Fi connections use a stable generated address (`wifi.cloned-mac-address=stable`) instead |
| `vendor/environment.d/50-omamobile-libcamera.conf` | `/usr/lib/environment.d` | `LIBCAMERA_SOFTISP_MODE=cpu` for the session (WirePlumber's libcamera plugin, omacam): the software ISP's GPU debayer faults on this GPU. environment.d can't unset a variable, so to try the GPU set `LIBCAMERA_SOFTISP_MODE=gpu` in `~/.config/environment.d/` |
| `bin/omamobile-ingot-firmware` | `/usr/bin` | Run by hand as root: installs the phone's own firmware from `modem_a` (see below). `plan`, `install [--dry-run] [--replace]`, `status`, `--help` |
| `share/firmware.map` | `/usr/share/omamobile/ingot/firmware.map` | What it copies (data, not code): `source-glob\|destination\|note` lines, and `wifi_board_name=` |
| `vendor/systemd/network/20-usb-gadget.network` | `/usr/lib/systemd/network` | Sets usb0 to 172.16.42.1/24 after handover. Same file as the Pixel 7 package |
| `vendor/systemd/logind.conf.d/10-omamobile-power-key.conf` | `/usr/lib/systemd/logind.conf.d` | A short power press does not power the phone off. Same drop-in as the Pixel 7 Pro package |
| `vendor/systemd/system/plymouth-quit.service.d/10-omamobile-retain-splash.conf` | `/usr/lib/systemd/system/plymouth-quit.service.d` | From 0.1.6: Plymouth quits with `--retain-splash`, so the Omarchy boot screen stays up until Hyprland draws, instead of a black panel while the session starts. The boot is quiet from `boot_a`'s command line (`quiet splash`, `device/ingot/initramfs/build`); without this drop-in the splash goes black a few seconds early. Same drop-in as the Pixel 7 Pro package |
| `vendor/NetworkManager/conf.d/10-omamobile-usb.conf` | `/usr/lib/NetworkManager/conf.d` | Keeps NetworkManager off that link |
| `etc/omamobile-mirrorlist` | `/etc/pacman.d/omamobile-mirrorlist` | Where pacman finds the `[omamobile]` repository. Same file as the Pixel 7 Pro package |
| `omamobile-device-ingot.install` | pacman hook | Adds `[omamobile]` to `pacman.conf` before `[omarchy]`, once. Same script as the Pixel 7 Pro package |
| `src/reboot-to.c` | `/usr/bin/reboot-to` | Reboot with a reason the bootloader understands. Same bytes as the Pixel 7 Pro package; the test checks. On the Saga, `reboot-to bootloader` reaches fastboot through PMK8350's SDAM |
| `device.conf` | `/usr/share/omamobile/device.conf` | The descriptor, the same bytes as `device/ingot/device.conf` |
| `version` | `/usr/share/omamobile/device-ingot/version` | The package version |

`./build [DIR]` compiles `reboot-to` from this directory, `./install DESTDIR [DIR]` stages the files, and `test/all` checks them (and runs the scripts against stand-ins: a made-up partition tree, sysfs, remoteproc and `btmgmt`) when it is run from the repository.

## The phone's own firmware: `omamobile-ingot-firmware`

The package ships no firmware. The GPU zap shader, the ADSP firmware and the Wi-Fi firmware and board data are the phone's own, on its `modem_a` partition (a FAT file system with Qualcomm's `image/` tree), and the tool copies them from there on the phone. SQE and GMU firmware and the Bluetooth firmware come from linux-firmware.

| Destination | From `modem_a` (unconfirmed names) | Used by |
| --- | --- | --- |
| `/usr/lib/firmware/qcom/sm8475/osom/ingot/a730_zap.mbn` (+ `a730_zap.bNN`) | `image/a730_zap.mdt` and its segments, or `image/a730_zap.mbn` | msm (the DT's `firmware-name`) |
| `/usr/lib/firmware/qcom/sm8475/osom/ingot/adsp.mdt` (+ `adsp.bNN`) | `image/adsp.mdt` and its segments, or `image/adsp.mbn` | the ADSP remoteproc |
| `/usr/lib/firmware/updates/ath11k/WCN6855/hw2.1/amss.bin` | `image/amss20.bin` (or one folder down) | ath11k |
| `/usr/lib/firmware/updates/ath11k/WCN6855/hw2.1/m3.bin` | `image/m3.bin` (or one folder down) | ath11k |
| `/usr/lib/firmware/updates/ath11k/WCN6855/hw2.1/regdb.bin` | `image/regdb.bin` (or one folder down) | ath11k |
| `/usr/lib/firmware/updates/ath11k/WCN6855/hw2.1/board-2.bin` | built from `image/bdwlang.elf` (or one folder down) and `wifi_board_name` | ath11k |

How it works, and what it refuses:

- It finds `modem_a` by `PARTNAME` in `/sys/class/block/*/uevent` and refuses unless there is exactly one, its `ro` reads 1 (the storage guard's; the tool never changes it) and it is not mounted. It checks that `/dev/<name>` is that partition's device number, mounts it read-only (`vfat`, `ro,nodev,nosuid,noexec`) on a private folder under `/run`, and always unmounts it. No other partition is read.
- Sources are matched without regard to case; each must match exactly one file. A missing or ambiguous source is reported and skipped; the others are still installed. A `.mdt` is copied with its `.bNN` segments, named after the destination (`a730_zap.mbn` gets `a730_zap.b00`, the name the kernel's loader asks for).
- Destinations must sit directly in the two firmware folders above; any other path in the map, `..` included, stops the run before anything is read.
- Files are installed 0644 root through a temporary file and a rename, read back, and recorded with their sha256 in `/var/lib/omamobile/ingot-firmware/installed.sha256`. A file already there that differs and is not in the record (a hand-installed copy), or that changed since this tool installed it, is kept and reported, and `install` exits 1; `--replace` overwrites it. `status` checks every recorded file.
- `board-2.bin` is ath11k's board container (`QCA-ATH11K-BOARD`, then one board element holding a name element and a data element, each 4-byte aligned, as `ath11k_core_fetch_board_data_api_n` reads it) around the phone's `bdwlang.elf`. The name is the one ath11k looks for, built from the bus, the PCI vendor, device and subsystem ids, the QMI chip and board ids and the DT's `qcom,calibration-variant`, so it can't be known offline: set `wifi_board_name=` in `/etc/omamobile/ingot-firmware.conf` (kept across updates; it wins over the map's empty default). Without it the board file is skipped. `plan` prints the name from this boot's `failed to fetch board data for <name>` lines, and builds the same name from the `chip_id ... board_id` line, the PCI device and the device tree, to compare. Note that the installed file hides linux-firmware's `board-2.bin`, so a wrong name leaves Wi-Fi without board data.

## Sound (0.1.5)

The card is a WCD938x codec and two WSA883x speaker amplifiers on SoundWire, behind the LPASS macros and the ADSP (`omamobile-adsp.service` must have started it). The kernel has no speaker protection for these amplifiers, so the profile is deliberately quiet:

- At boot (`BootSequence`) each amplifier's analog gain is set to 12 (-3 dB, its minimum; the kernel caps it at 17) and the WSA macro's digital gain to 70 (-14 dB; 84 is 0 dB, the kernel caps it at 81), with the macro's compander and the amplifiers' V/I sense off. No sequence raises them.
- The profile names no playback mixer element, so the desktop's volume is software only: it can attenuate from that level and nothing more. Raising the level means editing the two `WSA_RX* Digital Volume` lines, and is the owner's decision after listening.
- `Speaker` plays the left channel on `SpkrLeft` and the right on `SpkrRight`. `Earpiece` plays both channels mixed on `SpkrLeft` alone: the vendor's handset path is `SpkrLeft` and its speakerphone path `SpkrRight`. Neither has been confirmed by ear yet.
- `Mic` records the two digital microphones on the LPASS DMIC lines, DMIC1 (left; the vendor's handset microphone) and DMIC6 (right; its speakerphone microphone), through the VA macro. That needs a kernel whose device tree has the DMIC pins and a "VA Capture" link; the profile checks for the VA macro's controls and offers no `Mic` without them, so on an older kernel the phone has no microphone source. This path has not run on the phone yet. The WCD938x's analog inputs are not used: none of the four picked up a tone from the speakers, and the vendor records from the digital pair. USB-C analog headsets are not handled.

**The SoundWire rule is a workaround for two kernel faults**, both seen on 7.3-rc6:

- At the first clock stop and restart of the amplifiers' bus (`3250000.soundwire`, a few seconds after its last use) both amplifiers fall back to device number 0 at once, the controller's enumeration fails (`SWR bus clsh detected`, interrupt bit 11) and they stay `UNATTACHED` (`/sys/bus/soundwire/devices/sdw:1:*/status`). Streams then run without an error and without sound.
- The codec's buses survive the restart with parity errors and alerts, and an alert on the playback one (`3210000.soundwire`) ends in a NULL dereference in `wcd_interrupt_callback` (that device has no register map), which kills the bus's IRQ thread.

Held awake, the buses' clocks never stop at run time. That costs idle power. A system suspend stops the clocks all the same; in the suspends tried with the rule in place (`pm_test` runs and two suspend-to-idle cycles) the amplifiers were still `Attached` afterwards, so the failure seems to belong to the runtime path, and why is not understood. Check `/sys/bus/soundwire/devices/sdw:1:*/status` after a suspend before trusting it. Remove the rule once the kernel keeps the devices across a clock stop.

## After installing this version: remove the hand-installed copies

The bring-up system had these by hand. A file in `/etc` with the same name as a package file wins over it (`/etc/systemd/system` over `/usr/lib/systemd/system`, `/etc/modprobe.d` over `/usr/lib/modprobe.d`, `/etc/udev/rules.d` over `/usr/lib/udev/rules.d`), so the package's versions never apply while a copy is there. On the phone, after the update:

1. `omamobile-ingot-firmware plan`, then `omamobile-ingot-firmware install`. It keeps the hand-copied firmware that differs from `modem_a` and says so; files that match are adopted into the record. Once `plan` shows the same files, `install --replace` makes the record cover everything. Then `status`.
2. Remove the hand-written units for the ADSP start and the Bluetooth address from `/etc/systemd/system` (and their `*.wants/` links: `systemctl disable <unit>` first), then `systemctl daemon-reload`. Use `systemctl list-unit-files | grep -i -e adsp -e bt` to find them.
3. Remove the ath11k options file from `/etc/modprobe.d` (`grep -l ath11k /etc/modprobe.d/*`), and any `omamobile-*-bringup.conf` there.
4. Remove the hand-edited `.desktop` override that set `LIBCAMERA_SOFTISP_MODE=cpu` (in `~/.local/share/applications/`), so the session's environment applies.
5. Remove hand-copied udev rules from `/etc/udev/rules.d` that this package now ships (the storage, DMA-heap, Bluetooth and, from 0.1.5, SoundWire rules), then `udevadm control --reload`.
   From 0.1.5 the package also owns the sound profile under `/usr/share/alsa/ucm2/conf.d/sm8475/` and `/usr/share/alsa/ucm2/Solana/ingot/`, and the topology link `/usr/lib/firmware/updates/qcom/sm8475/SM8475-Solana-Saga-tplg.bin`. Hand-made copies there stop the upgrade ("exists in filesystem"): delete them first, or let pacman replace them with `--overwrite '/usr/share/alsa/ucm2/*' --overwrite '/usr/lib/firmware/updates/qcom/sm8475/*'`.
6. Remove a hand-made NetworkManager file in `/etc/NetworkManager/conf.d` that set the Wi-Fi MAC policy.
   From 0.1.6, also a hand copy of the Plymouth drop-in in `/etc/systemd/system/plymouth-quit.service.d/` (the bring-up phone tested the quiet boot with one), then `systemctl daemon-reload`.
7. Reboot once, then check the list below.

## Check on the phone

What could not be verified offline (the tests run every script against stand-ins only):

- `omamobile-ingot-firmware plan` on the phone: the real names under `image/` (the map's sources are unconfirmed: split or single zap and ADSP images, the Wi-Fi files' folder, `bdwlang.elf`), then correct `share/firmware.map`. That the kernel mounts `modem_a` as `vfat` (`CONFIG_VFAT_FS`), and that `findmnt` shows nothing left after a run.
- The board name: `plan`'s two names agree, Wi-Fi comes up with the built `board-2.bin` alone (no `failed to fetch board data` in `dmesg`), and throughput is no worse than with the hand-made board file.
- The zap shader under the `.mbn` name with `.bNN` segments loads (`dmesg | grep -i zap`), if the source turns out to be split.
- `omamobile-adsp.service` starts the ADSP at boot (`systemctl status omamobile-adsp`, `cat /sys/class/remoteproc/*/state`), the battery reads (`upower -d`) and the boot is not slower; that the remoteproc's `firmware` reads `qcom/sm8475/osom/ingot/adsp.mdt`.
- The Bluetooth unit runs for the controller (`systemctl status 'omamobile-bt-addr@*'`; the udev rule's `DRIVERS=="hci_uart_qca"` and `DEVTYPE` match), the controller leaves the unconfigured state (`btmgmt info`), keeps the same address across reboots, powers on and scans.
- `modinfo ath11k | grep dbg_` lists the three options on the running kernel, `cat /sys/module/ath11k/parameters/dbg_*` reads Y after boot, and Wi-Fi connects as before.
- NetworkManager applies the stable address (`nmcli -f GENERAL.HWADDR device show <ifname>` stays the same across reboots for a connection) and the `driver:ath11k_pci` match takes.
- `systemctl --user show-environment | grep LIBCAMERA` in the session, and omacam and PipeWire's camera node still stream (on the CPU).
- Sound, from 0.1.5: after a boot `cat /sys/devices/platform/soc@0/3250000.soundwire/power/control` reads `on` and both `/sys/bus/soundwire/devices/sdw:1:*/status` read `Attached`, also a minute after the session started; `wpctl status` lists a `Built-in Audio Speaker` sink; a quiet test tone is audible from both ends of the phone and undistorted; the earpiece device sounds at the ear end; on a kernel with the VA link, `wpctl status` lists the microphone source and speech is recorded on both of its channels.
- `ls -l /dev/sda /dev/sde` show mode 0000 after `udevadm trigger`, and the slot-A boot update, when it comes, still writes through the partition nodes.

## What stays manual, and why

- **Louder sound**: the amplifiers stay at their lowest gain until the kernel has speaker protection; see "Sound".
- **Fingerprint**: its trusted-app files live outside `modem_a` and have no Linux path yet.
- **Firmware from any partition but `modem_a`**: `modem_b`, `persist`, `modemst*`, `fsg`, `efs*` and `bluetooth_*` hold the phone's identity and calibration (or another slot's copy) and are never read by a package; a file that only exists there stays a hand step, with the owner's backup first.
- **The Wi-Fi board name**: set once per phone in `/etc/omamobile/ingot-firmware.conf`, because it can only be read on the phone.
- **Running `omamobile-ingot-firmware` itself**: by hand, as root, after an install or a stock update that changed `modem_a`; a package hook would mount a modem partition on every upgrade.

Not in this package: the boot-success marker, the modem, the charger guard and the cameras' bring-up. Those stay out until each one has its own runbook.
