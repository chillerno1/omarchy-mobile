<!-- SPDX-License-Identifier: MIT -->
# lpac (Omarchy Mobile build)

lpac 2.3.0, the Linux eSIM LPA (SGP.22 Local Profile Assistant), built
with the QMI-over-QRTR APDU backend for the Solana Mobile Saga (ingot):
its eUICC is reached through the modem's QMI UIM service over QRTR, with
no `/dev/cdc-wdm` device. Neither Arch Linux nor Arch Linux ARM packages
lpac, so the Saga's eSIM steps need this.

Build it for aarch64 on the laptop (Arch Linux ARM container):

```sh
tools/build-packages --local ingot packages/lpac
```

| Piece | Use |
| --- | --- |
| `/usr/bin/lpac` | The LPA: prints JSON on stdout |
| `LPAC_APDU=qmi_qrtr` | Talk to the eUICC through QMI UIM over QRTR (the Saga) |
| `LPAC_APDU_QMI_UIM_SLOT` | UIM slot for the qmi and qmi_qrtr backends (default 1) |
| `LPAC_APDU=qmi`, `at`, `pcsc` | The other backends built in (cdc-wdm, AT port, PC/SC reader) |
| `LPAC_HTTP=curl` | HTTP to the SM-DP+ (the only HTTP backend built) |
| `/usr/share/doc/lpac/` | Upstream `USAGE.md`, `ENVVARS.md`, `FAQ.md` |

- Read-only first: `lpac chip info` and `lpac profile list` change
  nothing. `profile download`, `enable`, `disable`, `delete` and
  `notification process` change the eUICC or tell the carrier.
- libeuicc and the drivers are linked in statically (one package, no
  `libeuicc.so`); cJSON is upstream's vendored copy (2.3.0 has no option
  to use a system cjson).
- Licences: lpac AGPL-3.0-only, libeuicc LGPL-2.1-only, cJSON MIT
  (`/usr/share/licenses/lpac/`).
- `lpac version` is stamped in `prepare()`: upstream's tarball build says
  `v0.0.0-unknown` because the version applet includes its own
  `version.h`, not the generated one.
- Status: built for aarch64 in the Arch Linux ARM container (2026-11-12);
  `lpac version` and `LPAC_APDU=qmi_qrtr lpac chip info` run there (the
  latter stops at "connect to QRTR bus failed", as it must without a
  modem). Not run on a phone yet: the Saga's modem is not started.
