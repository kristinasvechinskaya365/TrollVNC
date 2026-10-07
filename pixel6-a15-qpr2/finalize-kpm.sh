#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/output-pixel6-a15}"
PAYLOAD="${PAYLOAD:-$ROOT/output-pixel-kpm-farbranch}"
WORK="${WORK:-$ROOT/work-pixel6-a15}"
die() { echo "ERROR: $*" >&2; exit 1; }

[[ -s "$OUT/Image.pre-kpm" && -s "$OUT/config" ]] || die 'core build is missing'
[[ -s "$PAYLOAD/kpimg" && -x "$PAYLOAD/kptools-linux" ]] || die 'pinned KPM payload is missing'
grep -qxF 'KPM_FAR_BRANCH_BUILD=PASS' "$PAYLOAD/proof.txt" || die 'KPM build proof missing'
grep -qxF 'KPM_FAR_BRANCH_RANGE_SELFTEST=PASS' "$PAYLOAD/proof.txt" || die 'KPM branch range test missing'
grep -qxF 'KERNELPATCH_SOURCE_REF=e565c93ff6d0b992d9dfcbd43533a49d744a5f23' "$PAYLOAD/proof.txt" || die 'unexpected KPM source'
grep -qxF 'CONFIG_KPM=y' "$OUT/config" || die 'KPM is absent from the built kernel'

# Ephemeral standalone KernelPatch key; SukiSU manager uses its own control path.
key="$(openssl rand -hex 24)"
[[ "${#key}" -eq 48 ]] || die 'KPM key generation failed'
"$PAYLOAD/kptools-linux" -p -i "$OUT/Image.pre-kpm" -k "$PAYLOAD/kpimg" -S "$key" -o "$OUT/Image.tmp" > /tmp/kpm-patch-private.log 2>&1
rm -f /tmp/kpm-patch-private.log
unset key
[[ -s "$OUT/Image.tmp" ]] || die 'KPM tool produced no Image'

before="$(strings "$OUT/Image.pre-kpm" | awk '/^Linux version / && !found {print $3; found=1}')"
after="$(strings "$OUT/Image.tmp" | awk '/^Linux version / && !found {print $3; found=1}')"
[[ -n "$before" && "$before" == "$after" && "$after" == 6.1.* ]] || die 'KPM changed the kernel release'
! cmp -s "$OUT/Image.pre-kpm" "$OUT/Image.tmp" || die 'KPM did not modify the Image'
grep -aFq 'KPM_FAR_BRANCH_VENEER' "$OUT/Image.tmp" || die 'KPM far branch marker missing'
"$PAYLOAD/kptools-linux" -l -i "$OUT/Image.tmp" > /tmp/kpm-image-info-private.txt
grep -qxF 'patched=true' /tmp/kpm-image-info-private.txt || die 'postpatch verification failed'
grep -qxF 'version=0xd00' /tmp/kpm-image-info-private.txt || die 'unexpected KernelPatch version'
grep -qxF 'superkey=' /tmp/kpm-image-info-private.txt || die 'plaintext key embedded in Image'

printf 'patched=true\nversion=0xd00\n' > "$OUT/kpm-image-info.txt"
rm -f /tmp/kpm-image-info-private.txt
mv "$OUT/Image.tmp" "$OUT/Image"
"$WORK/aosp/scripts/extract-ikconfig" "$OUT/Image" > "$OUT/config.post-kpm"
cmp "$OUT/config" "$OUT/config.post-kpm" || die 'KPM changed the embedded config'
gzip -c "$OUT/Image" > "$OUT/Image.gz"
cp "$PAYLOAD/proof.txt" "$OUT/kpm-payload-proof.txt"
sha256sum "$OUT/Image.pre-kpm" "$OUT/Image" "$OUT/Image.gz" > "$OUT/SHA256SUMS"
mv "$OUT/dist" "$OUT/source-dist-before-kpm"
cat >> "$OUT/provenance.txt" <<EOF
kpm_postpatch=PASS
kpm_source=e565c93ff6d0b992d9dfcbd43533a49d744a5f23
kpm_kernel_release=$after
kpm_runtime=NOT_YET_TESTED
physical_boot=NOT_YET_TESTED
EOF
echo 'PIXEL6_A15_QPR2_KPM_POSTPATCH=PASS'
