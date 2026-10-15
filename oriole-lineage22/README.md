# Pixel 6 / oriole — LineageOS 22.2 kernel port

This branch ports the already-verified Pixel 6 Android 15 SukiSU/KPM/SUSFS 2.3 recipe onto the pinned blu_spark A15 source. It is build-only staging. No private application source, credentials, ROM signing keys or device serials are included.

## What is implemented

- Pinned blu_spark A15 `blu_spark-15-61` source `536518ba56c64865b05abce6618077d91d3ef07e`.
- Pinned successful recipe `6374b323b459b8be265fae28b897e1cb578daf67` from this public mirror.
- Replacement, not stacking, of the upstream KernelSU provider with the existing SukiSU Ultra builtin UAPI 5 implementation.
- SUSFS **2.3.0**, all nine options required in the compiled configuration: SUS_PATH, SUS_MOUNT, SUS_KSTAT, SPOOF_UNAME, ENABLE_LOG, HIDE_KSU_SUSFS_SYMBOLS, SPOOF_CMDLINE_OR_BOOTCONFIG, OPEN_REDIRECT and SUS_MAP.
- KPM build and final Image patching, preserved BBG profile, exact patch dry-run, source locks and strict binary/configuration checks.
- 21 local regression tests, including absent features, duplicate root providers, symlink handling and low-level firmware exclusion.
- GitHub Actions: source-port audit first, kernel compilation only after the audit succeeds; failure logs retained.

## Run locally

From a checkout of this branch on an Internet-connected Linux build host:

```sh
python3 -m unittest discover -s oriole-lineage22 -p 'test_*.py' -v
python3 oriole-lineage22/build.py port-audit /absolute/new/path/port-audit
python3 oriole-lineage22/build.py prepare /absolute/new/path/build-work --variant blu-spark
```

The workflow installs the NDK, builds KPM, runs the prepared `pixel6-a15-qpr2/build.sh`, finalizes KPM and verifies the result. Kernel compilation needs the full pinned Google Pixel vendor/module topology and adequate disk space; it is not just an Image replacement on a generic emulator kernel.

## Meaning of the output

`Image.gz` is a kernel payload, NOT an installer. `candidate-status.json` keeps `rom_built=false`, `flash_ready=false`, and physical/firmware compatibility `NOT_TESTED`. Successful compilation cannot establish Android 17-to-15 bootability.

The pinned A15 blu_spark branch identifies itself as Linux 6.1.99. Rebuilding it does not make security coverage current. Backport coverage and the LineageOS framework security patch level are explicitly not yet audited; do not relabel this as an up-to-date security release.

Remaining integration gates: identify/authenticate the exact oriole LineageOS 22.2 ROM, inspect its OTA payload and all low-level firmware writes, match kernel/module CRCs and boot/vendor_boot/DTBO layout, package the matching boot image and recovery inputs, then physically qualify boot and hardware on the intended starting firmware. No low-level bootloader downgrade, radio flash, slot switch, wipe or relock is executed by this tooling.

The original emulator kernel is not a Pixel 6 hardware kernel. The reused recipe here is specifically the existing GS101/oriole Android 15 kernel recipe.
