<!-- SPDX-License-Identifier: MIT -->
# tqftpserv (Omarchy Mobile build)

tqftpserv 1.3 (with the two upstream fixes since), the TFTP server that
Qualcomm remote processors reach over QRTR (AF_QIPCRTR). On the Solana
Mobile Saga (ingot) the modem (MPSS) uses it to read its carrier
configuration (`/readonly/firmware/image/modem_pr/mcfg/...`) and to keep
small read-write files (`/readwrite/...`). Neither Arch Linux nor Arch
Linux ARM packages it.

Build it for aarch64 on the laptop (Arch Linux ARM container):

```sh
tools/build-packages --local ingot packages/tqftpserv
```

| Piece | Use |
| --- | --- |
| `/usr/bin/tqftpserv` | The server; logs each request (`[TQFTP] RRQ: ...`) |
| `tqftpserv.service` | Runs it (`Restart=always`, `StateDirectory=tqftpserv`) |
| `tqftpserv-populate-readwrite.service` | Oneshot before it: mounts the `persist` partition read-only and copies `rfs/msm/mpss/` into `/var/lib/tqftpserv` |
| `/usr/libexec/tqftpserv/populate-readwrite.sh` | What that oneshot runs |

- Paths: `/readonly/firmware/image/<file>` is served from `/lib/firmware`
  (following the modem's `firmware-name` in the device tree, and `.xz` or
  `.zst` files); `/readwrite/<file>` from `/var/lib/tqftpserv`.
- Both units are installed, not enabled. On the Saga, never enable
  `tqftpserv-populate-readwrite.service`: it mounts `persist`, which this
  project never mounts (AGENTS.md section 1). `tqftpserv.service` alone,
  with an empty `/var/lib/tqftpserv`, is enough: the modem writes its own
  small files there.
- Depends on `qrtr` (libqrtr), which Arch Linux ARM's `[aur]` repository
  provides as `qrtr-git`.
- 0001 and 0002 are the upstream commits after v1.3: `_GNU_SOURCE` for
  `asprintf()`, and the helper script in `/usr/libexec/tqftpserv`.
- Status: built for aarch64 in the Arch Linux ARM container (2026-11-12,
  `tools/build-packages --local ingot`); not run on a phone yet: the Saga's
  modem is not started.
