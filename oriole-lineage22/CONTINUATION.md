# Current executable checkpoint — 2026-10-15 UTC

**This section supersedes older historical claims below.** Canonical source builds on corrected v2 and now includes two scoped source-maintenance fixes and a mandatory source-tree filesystem-integrity guard.

- Real Linux pinned source audits succeeded through `ede749a02479c942c517eb1759ed2a7e61927472`, including the exact PREIMAGE-bound AEAD fixes for CVE-2026-31431 and CVE-2026-43077. These are only scoped source fixes, not comprehensive kernel/framework/vendor security maintenance.
- M2 native smoke build `38666437571` failed at `xt_DSCP.o` because the macOS checkout was case-insensitive. Live read-only bridge receipt `oriole-case-collision-20261015T1345-f7a23d91` confirmed one case-folded file instead of both `xt_DSCP.c` and `xt_dscp.c`.
- Required four independent source-file pairs are now checked at source-audit entry by `2dc8bbaaebc97406f9fa767d147fe7dac46dac6c` and tested by `4eb4ae00d1d4a0981fb07b0465c3ac7996cb39bb`. The previous macOS source audit must not be treated as proof of complete checkout integrity.
- `124/124` host tests pass when supplied with the independently SHA-verified **historical** Pixel kernel as a fixture (this image is not the new requested build).
- New self-hosted private M2 Linux Docker **case-sensitive-volume** source compilation was running at GitHub Actions run `38745677343`, job `116458561125`, when this checkpoint was authored. Do not assert success without an actual finished run and authenticated resulting Image.
- Complete Google Kleaf/KPM/vendor modules build, real LineageOS 22.2 API35 product, signing, full payload/firmware auditing, physical recovery transport, backup and device qualification remain incomplete. Wi-Fi ADB must not be treated as Fastboot connectivity, and no installation has occurred.

---

# Continuation: binary identity, full source integration, and OTA audit

## Verified locally

- 86 tests pass with the real preserved baseline enabled. Without the baseline path, CI runs 85 tests and explicitly skips that one external-fixture test.
- 5,000 deterministic malformed protobuf inputs produced no unexpected exceptions.
- A regression was reproduced in the first version: `verify_output(..., "blu-spark")` accepted the old baseline kernel. The new checker requires the expected release identity from the actual Image, rejects conflicting banners, and checks all 38 options against the embedded IKCONFIG stream.
- The genuine baseline still passes its own variant check and is rejected as blu_spark. The exact baseline Image SHA-256 is `754f203caa426b47665643ad6cbff1bbe73d5ba4e64c0b1c931e936801ee4012`.
- All twelve KPM bridge symbols and the SUSFS/BBG initializers are required. Configuration sidecars must equal the embedded configuration. A failed recheck removes a stale success report.

## Build changes

The source-port job now exercises the complete existing integration fragment: SukiSU restoration, integration regression tests/repairs, KPM bridges, exact SUSFS patch application, and the BBG/profile source checks. It runs before the large Google toolchain/vendor-project sync. This code path is prepared, not reported as executed against real sources in this continuation.

A standalone two-minute runner probe has no checkout or network dependency. It distinguishes runner allocation from source/build failures when GitHub executes it. The regular workflow retains source integration evidence and module-symbol-version outputs in addition to the previous logs.

## Real OTA inspection

```sh
python3 oriole-lineage22/ota_audit.py EXACT_ORIOLE_A15_OTA.zip \
  --expected-sha256 PUBLISHER_VERIFIED_64_HEX_SHA256 \
  --output ota-audit.json
```

The inspector requires a known whole-ZIP SHA-256, validates Pixel 6/API 35 metadata and actual payload/property hashes, decodes the real CrAU/protobuf partition inventory, checks operation/extent bounds, and reports low-level firmware, unknown partitions, postinstall executables and nested installer files. Partition image hashes are declarations from the manifest, not independently reconstructed image hashes. ZIP/payload consistency is not signer authentication.

The tool never executes the installer or issues adb/fastboot commands. `flash_ready=false` and `firmware_preservation_proven=false` remain explicit even for a clean partition inventory. Signed packages still need independent signer verification and postinstall review. No real LineageOS OTA binary was available for this continuation; OTA tests use generated fixtures, not a claimed physical-device result.

## Current external blockers

The container cannot resolve GitHub/Google source hosts. The one bounded retry of private run 38647577754 failed again before any steps (port-audit job 116166565487; kernel skipped). The public fallback had no run before the continuation commit. Repository metadata establishes that TrollVNC is a public fork; the connector does not expose Actions enablement or new-repository creation. Fork status alone does not prove the exact missing-trigger cause. Do not keep submitting blind retries.

No new kernel compilation, full LineageOS build, security-backport coverage, boot-image packaging, or CP3A.260905.009 compatibility is certified. The A15 baseline is retained honestly; a rebuild is not a new security patch level.

## Source references

- AOSP payload schema: https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto (observed blob 6d16da40e53720078b2e4f3689dbb296eb325bee)
- Payload property hashing: https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/payload_generator/payload_properties.cc
- Pinned build references remain in build.py and each generated source-lock.json.
