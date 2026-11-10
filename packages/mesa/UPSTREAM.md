<!-- SPDX-License-Identifier: MIT -->
# Upstream merge request: Mali-G710 model entry

Target: `mesa/mesa` on gitlab.freedesktop.org, branch `main`, labels
`panfrost` and `panvk`. Once it is merged, nominate it for the current stable
branch with `Cc: mesa-stable`.

**Do not open the MR until gate G2 has passed.** The "Testing" section needs
real results from the phone. Replace every `TODO` first.

---

## Title

panfrost: add Mali-G710 to the model table

## Description

Mali-G710 is the GPU in Google Tensor G2 (gs201, Pixel 7 / 7 Pro / 7a /
Fold / Tablet), MediaTek Dimensity 9000 and others. The upstream Panthor
kernel driver already names it (`GPU_PROD_ID_MAKE(10, 2)` → "Mali-G710" in
`drivers/gpu/drm/panthor/panthor_hw.c`). Mesa has no entry for it in
`pan_model_list`, so on these devices:

- the Gallium driver fails `pan_get_model()` and does not create a screen;
- PanVK fails with `VK_ERROR_INCOMPATIBLE_DRIVER` ("Unknown gpu_id").

The change is one line:

```c
VALHALL_MODEL(PAN_PROD_ID(10, 8, 2), 0, "G710", "G710", MODEL_ANISO(ALL), MODEL_TB_SIZES(32768, 16384),
              MODEL_RATES_X(4, 8, 16, 64, 64, 16)),
```

Why these values:

- **Product ID.** GPU_ID on the Pixel 7 Pro is `0xa862xxxx`: arch 10.8,
  arch_rev 6, product major 2. The stock kbase driver logs "GPU identified as
  0x2 arch 10.8.6 r0p0". `PAN_PROD_ID(10, 8, 2)` follows from that.
- **Variant 0.** `gpu_variant` is `GPU_CORE_FEATURES & 0xff`. It is 0 on
  G610 (10.8.7) and was confirmed 0 on G710: TODO paste `core_features`
  from the Panthor `DEV_QUERY`.
- **Tile buffer, rates and anisotropy.** These are the G610 values. G610 and
  G710 use the same Valhall shader core, with G610 as the smaller
  configuration, so per-core throughput and tile-buffer sizes are the same.
  The performance-counter layout is already the "G710" one that G610 uses
  (`src/panfrost/perf/meson.build`).
- **Firmware.** Panthor loads `arm/mali/arch10.8/mali_csffw.bin`, the same
  file as G610 (linux-firmware).

## Testing

Pixel 7 Pro (gs201, Mali-G710 MC7 r0p0), mainline Linux 7.3 with Panthor,
Arch Linux ARM, Mesa 26.2.4 + this patch:

- `dmesg`: TODO (Panthor probe lines: id, shader_present, FW version)
- `eglinfo -B`: TODO (renderer string)
- `glmark2-es2-drm`: TODO (score, no faults)
- `vulkaninfo --summary`, `vkcube --wsi display`: TODO
- dEQP-GLES3 / dEQP-VK smoke subset: TODO (pass/fail/crash counts)

## Commit

The patch is `0001-panfrost-add-Mali-G710-to-the-model-table.patch` in this
directory, written against 26.2.4. Against `main` (checked 2026-10-11, where
G68/G715/G615 have been added) it applies with fuzz 2, so rebase it onto
`main` and push a clean commit rather than sending this file as is.

---

## Already upstream: llvmpipe on aarch64 without SVE

`0011-gallivm-Query-host-CPU-features-on-aarch64-too.patch` needs no merge
request. It is upstream's [65b4a553](https://gitlab.freedesktop.org/mesa/mesa/-/commit/65b4a553b3f54f62f0732c7c249a8da56d3b27fa)
([!45130](https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/45130),
closes [work item 13314](https://gitlab.freedesktop.org/mesa/mesa/-/work_items/13314)),
picked to the 26.2 branch as [0e230a5f](https://gitlab.freedesktop.org/mesa/mesa/-/commit/0e230a5ffcf2b05598ace6662374b351533cf523)
([!45215](https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/45215)) and
released in Mesa 26.2.5. The file is that stable pick unchanged, without its
`.pick_status.json` hunk; it applies to 26.2.4 with no offset. Drop it when
rebasing onto 26.2.5 or later.
