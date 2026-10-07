#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECIPE="$ROOT/pixel6-a15-qpr2"
WORK="${WORK:-$ROOT/work-pixel6-a15}"
OUT="${OUT:-$ROOT/output-pixel6-a15}"
SUKISU_REF=70fa0e092a2c81060823f8ae526eac14fdda2930
SUSFS_REF=24743360ea08d98f6ad72b856851abed8de5854f
die() { echo "ERROR: $*" >&2; exit 1; }
[[ ! -e "$WORK" && ! -e "$OUT" ]] || die 'work/output already exists'
mkdir -p "$WORK" "$OUT"
cd "$WORK"
git config --global user.email kernel-builder@localhost
git config --global user.name KernelBuilder
repo init -u https://android.googlesource.com/kernel/manifest -b cd52bcfd387b36dab1f2f9e632998b477b0aa35a --depth=1
cp "$RECIPE/default.xml" .repo/manifests/default.xml
repo sync -c --no-tags -j4 --fail-fast
repo manifest -r > "$OUT/resolved-manifest.xml"
[[ "$(git -C aosp rev-parse HEAD)" == 3c76c2d71bb32039037c6f5dc38b172fe4142bdb ]] || die 'kernel pin mismatch'
git clone --branch builtin https://github.com/SukiSU-Ultra/SukiSU-Ultra.git KernelSU
git -C KernelSU checkout --detach "$SUKISU_REF"
git clone --branch gki-android14-6.1 https://github.com/ShirkNeko/susfs4ksu.git susfs4ksu
git -C susfs4ksu checkout --detach "$SUSFS_REF"
grep -qxF '#define SUSFS_VERSION "v2.3.0"' susfs4ksu/kernel_patches/include/linux/susfs.h
cp -a KernelSU/kernel aosp/drivers/kernelsu
python3 "$RECIPE/test-sukisu-kpm.py" KernelSU/kernel | tee "$OUT/sukisu-kpm-host-proof.txt"
python3 "$RECIPE/repair-sukisu-kpm.py" aosp/drivers/kernelsu
diff -u KernelSU/kernel/kpm/kpm.c aosp/drivers/kernelsu/kpm/kpm.c > "$OUT/sukisu-kpm-handler.patch" || [[ "$?" == 1 ]]
diff -u KernelSU/kernel/kpm/super_access.c aosp/drivers/kernelsu/kpm/super_access.c > "$OUT/sukisu-kpm-struct.patch" || [[ "$?" == 1 ]]
printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> aosp/drivers/Makefile
printf '\nsource "drivers/kernelsu/Kconfig"\n' >> aosp/drivers/Kconfig
python3 - <<'PY'
from pathlib import Path
p=Path('aosp/drivers/kernelsu/Kconfig')
s=p.read_text(); a=s.index('config KPM\n'); b=s.index('\nmenu ',a)
block=s[a:b]
assert block.count('default n')==1
p.write_text(s[:a]+block.replace('default n','default y')+s[b:])
# Remove network-derived version labels: the source SHA is the version identity.
# Numeric version freezes upstream's main-derived value at main SHA
# 42d7fda3d787b7df90fc440a50bb9c8216a3fdef (3774 commits), rather than
# deriving a lower value from builtin's separate 814-commit history.
p=Path('aosp/drivers/kernelsu/Makefile');s=p.read_text()
a=s.index('git_short_sha    =');b=s.index('$(info -- $(REPO_NAME) version:',a)
s=s[:a]+'KSU_VERSION := 40959\nKSU_VERSION_FULL := v4.2.0-70fa0e09@builtin\n'+s[b:]
p.write_text(s)
# KPM selects KALLSYMS_ALL. Kconfig's canonical savedefconfig omits this
# redundant line; verify.py still requires CONFIG_KALLSYMS_ALL=y in Image.
p=Path('aosp/arch/arm64/configs/gki_defconfig');s=p.read_text()
assert s.count('CONFIG_KALLSYMS_ALL=y\n')==1
p.write_text(s.replace('CONFIG_KALLSYMS_ALL=y\n','',1))
# Add only the twelve declared SukiSU KPM bridge exports to the KMI allowlist.
# Keep strict mode and symbol trimming; do not bypass either check.
import re
exports=set()
for f in Path('aosp/drivers/kernelsu/kpm').glob('*.c'):
    exports.update(re.findall(r'EXPORT_SYMBOL\((\w+)\)',f.read_text()))
assert len(exports)==12,sorted(exports)
Path('aosp/android/abi_gki_aarch64_sukisu').write_text('[abi_symbol_list]\n'+''.join('  '+x+'\n' for x in sorted(exports)))
p=Path('aosp/BUILD.bazel');s=p.read_text();anchor='        "android/abi_gki_aarch64_sunxi",\n'
assert s.count(anchor)==1
p.write_text(s.replace(anchor,'        "android/abi_gki_aarch64_sukisu",\n'+anchor,1))
PY
patch --dry-run --fuzz=0 -p1 -d aosp < "$RECIPE/susfs-raviole.patch"
patch --fuzz=0 -p1 -d aosp < "$RECIPE/susfs-raviole.patch"
cp susfs4ksu/kernel_patches/fs/susfs.c aosp/fs/
cp susfs4ksu/kernel_patches/include/linux/susfs{,_def}.h aosp/include/linux/
! find aosp -name '*.rej' -print -quit | grep -q . || die 'rejected patch'
cp "$RECIPE/susfs-raviole.patch" "$OUT/"
BUILD_AOSP_KERNEL=1 ./build_raviole.sh --config=no_download_gki --config=no_download_gki_fips140 -- --dist_dir="$OUT/dist"
[[ -s "$OUT/dist/Image" ]] || die 'no source Image in dist'
aosp/scripts/extract-ikconfig "$OUT/dist/Image" > "$OUT/config"
python3 "$RECIPE/verify.py" "$OUT" aosp
cp "$OUT/dist/Image" "$OUT/Image.pre-kpm"
cat > "$OUT/provenance.txt" <<EOF
device=oriole
platform=Android 15 QPR2 source target
manifest=reconstructed official topology with 80 stable project revisions pinned
common_commit=3c76c2d71bb32039037c6f5dc38b172fe4142bdb
sukisu_commit=$SUKISU_REF
susfs_commit=$SUSFS_REF
susfs_version=v2.3.0
kernel_config_check=PASS
kpm_runtime=NOT_YET_TESTED
physical_boot=NOT_YET_TESTED
EOF
