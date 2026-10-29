# omamobile-device-ingot

Omarchy Mobile's first userspace package for the Solana Mobile Saga (codename ingot, SM8475). It hides the Android partitions from desktop tools, holds the USB link to the host, and keeps a short power press from powering the phone off.

| Path | Installs to | What it does |
| --- | --- | --- |
| `vendor/udev/rules.d/10-omamobile-storage.rules` | `/usr/lib/udev/rules.d` | Hides `sda` and every Android partition except `userdata` from desktop tools. Like the Pixel 7 Pro's rule, over all eight of the Saga's LUNs (`sda` to `sdh`) |
| `vendor/systemd/network/20-usb-gadget.network` | `/usr/lib/systemd/network` | Sets usb0 to 172.16.42.1/24 after handover. Same file as the Pixel 7 package |
| `vendor/systemd/logind.conf.d/10-omamobile-power-key.conf` | `/usr/lib/systemd/logind.conf.d` | A short power press does not power the phone off. Same drop-in as the Pixel 7 Pro package |
| `vendor/NetworkManager/conf.d/10-omamobile-usb.conf` | `/usr/lib/NetworkManager/conf.d` | Keeps NetworkManager off that link |
| `etc/omamobile-mirrorlist` | `/etc/pacman.d/omamobile-mirrorlist` | Where pacman finds the `[omamobile]` repository. Same file as the Pixel 7 Pro package |
| `omamobile-device-ingot.install` | pacman hook | Adds `[omamobile]` to `pacman.conf` before `[omarchy]`, once. Same script as the Pixel 7 Pro package |
| `src/reboot-to.c` | `/usr/bin/reboot-to` | Reboot with a reason the bootloader understands. Same bytes as the Pixel 7 Pro package; the test checks. On the Saga, `reboot-to bootloader` reaches fastboot through PMK8350's SDAM |
| `device.conf` | `/usr/share/omamobile/device.conf` | The descriptor, the same bytes as `device/ingot/device.conf` |

`./build [DIR]` compiles `reboot-to` from this directory, `./install DESTDIR [DIR]` stages the files, and `test/all` checks the copies when it is run from the repository.

Not in this package: the boot-success marker, Wi-Fi, the charger, cameras and the GPU. Those stay out until each one has its own runbook.
