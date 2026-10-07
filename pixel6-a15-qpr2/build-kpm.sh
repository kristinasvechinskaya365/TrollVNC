#!/usr/bin/env bash
set -euo pipefail

# Build a SukiSU-compatible KernelPatch payload with AArch64 far CALL26/JUMP26
# veneers. The Pixel GKI kernel itself is not rebuilt here; this produces a
# replacement kpimg + kptools pair for controlled post-processing/testing.

SRC_REPO='https://github.com/SukiSU-Ultra/SukiSU_KernelPatch_patch.git'
SRC_REF='e565c93ff6d0b992d9dfcbd43533a49d744a5f23'
EXPECTED_VERSION_HEX='0x000d00'
OUT="${OUT:-$PWD/output-pixel-kpm-farbranch}"
WORK="${WORK:-/tmp/pixel-kpm-farbranch-${GITHUB_RUN_ID:-$$}}"
TARGET_COMPILE="${TARGET_COMPILE:-}"

fail(){ echo "ERROR: $*" >&2; exit 1; }
for c in git python3 grep strings sha256sum make cmake; do
  command -v "$c" >/dev/null 2>&1 || fail "$c not found"
done
[[ -n "$TARGET_COMPILE" ]] || fail 'TARGET_COMPILE must point to the Android NDK LLVM bin directory'
[[ -x "$TARGET_COMPILE/aarch64-linux-android35-clang" ]] || fail "Android clang missing: $TARGET_COMPILE/aarch64-linux-android35-clang"
[[ -x "$TARGET_COMPILE/ld.lld" ]] || fail "ld.lld missing: $TARGET_COMPILE/ld.lld"
[[ -x "$TARGET_COMPILE/llvm-objcopy" ]] || fail "llvm-objcopy missing: $TARGET_COMPILE/llvm-objcopy"

rm -rf "$WORK" "$OUT"
mkdir -p "$WORK" "$OUT"
SRC="$WORK/KernelPatch"

echo '=== FETCH PINNED SUKISU KERNELPATCH SOURCE ==='
git clone --quiet "$SRC_REPO" "$SRC"
git -C "$SRC" checkout --quiet --detach "$SRC_REF"
git -C "$SRC" submodule update --init --recursive --quiet
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$SRC_REF" ]] || fail 'source pin mismatch'

echo '=== APPLY KPM FAR-BRANCH VENEER PATCH ==='
python3 - "$SRC" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
hdr = root / 'kernel/patch/include/module.h'
modc = root / 'kernel/patch/module/module.c'
relo = root / 'kernel/patch/module/relo.c'

# 1) Keep the veneer storage inside each KPM's single ROX allocation.
s = hdr.read_text()
old = '''    void *start;\n\n    struct list_head list;\n'''
new = '''    void *start;\n\n    /* Reserved at the end of the same ROX allocation as the KPM image.\n     * Each 16-byte slot is used only when a CALL26/JUMP26 target is outside\n     * the AArch64 +/-128 MiB direct-branch window. */\n    void *branch_veneer;\n    unsigned int branch_veneer_offset;\n    unsigned int branch_veneer_count;\n    unsigned int branch_veneer_used;\n\n    struct list_head list;\n'''
if s.count(old) != 1:
    raise SystemExit(f'ERROR: module.h anchor count={s.count(old)}')
hdr.write_text(s.replace(old, new, 1))

# 2) Count every branch relocation before allocation and reserve one slot for
# each. This is intentionally conservative: direct branches consume no slot at
# runtime, while every possible far branch has guaranteed capacity.
s = modc.read_text()
inc_anchor = '#include <uapi/asm-generic/errno.h>\n'
inc_new = inc_anchor + '#include <linux/elf.h>\n#include <uapi/linux/elf.h>\n#include <asm/elf.h>\n'
if s.count(inc_anchor) != 1:
    raise SystemExit(f'ERROR: module.c ELF include anchor count={s.count(inc_anchor)}')
s = s.replace(inc_anchor, inc_new, 1)

anchor = '''static int rewrite_section_headers(struct load_info *info)\n{\n'''
helper = r'''#define KPM_BRANCH_VENEER_SIZE 16U

static unsigned int count_branch_veneer_slots(const struct load_info *info)
{
    unsigned int i, j, count = 0;

    for (i = 1; i < info->hdr->e_shnum; i++) {
        const Elf_Shdr *rsec = &info->sechdrs[i];
        unsigned int target_sec = rsec->sh_info;
        Elf64_Rela *rel;

        if (rsec->sh_type != SHT_RELA || target_sec >= info->hdr->e_shnum)
            continue;
        if (!(info->sechdrs[target_sec].sh_flags & SHF_ALLOC))
            continue;

        rel = (Elf64_Rela *)rsec->sh_addr;
        for (j = 0; j < rsec->sh_size / sizeof(*rel); j++) {
            unsigned int type = ELF64_R_TYPE(rel[j].r_info);
            if (type == R_AARCH64_CALL26 || type == R_AARCH64_JUMP26)
                count++;
        }
    }
    return count;
}

'''
if s.count(anchor) != 1:
    raise SystemExit(f'ERROR: module.c helper anchor count={s.count(anchor)}')
s = s.replace(anchor, helper + anchor, 1)

layout_anchor = '''    layout_sections(mod, info);\n    layout_symtab(mod, info);\n\n    if ((rc = move_module(mod, info))) goto free;\n'''
layout_new = '''    layout_sections(mod, info);\n    layout_symtab(mod, info);\n\n    mod->branch_veneer_count = count_branch_veneer_slots(info);\n    if (mod->branch_veneer_count) {\n        mod->branch_veneer_offset = ALIGN(mod->size, 16);\n        mod->size = mod->branch_veneer_offset +\n                    mod->branch_veneer_count * KPM_BRANCH_VENEER_SIZE;\n        logki("KPM branch veneer reserve: slots=%u offset=%x total=%x\\n",\n              mod->branch_veneer_count, mod->branch_veneer_offset, mod->size);\n    }\n\n    if ((rc = move_module(mod, info))) goto free;\n'''
if s.count(layout_anchor) != 1:
    raise SystemExit(f'ERROR: module.c layout anchor count={s.count(layout_anchor)}')
s = s.replace(layout_anchor, layout_new, 1)

move_anchor = '''    memset(mod->start, 0, mod->size);\n\n    /* Transfer each section which specifies SHF_ALLOC */\n'''
move_new = '''    memset(mod->start, 0, mod->size);\n    if (mod->branch_veneer_count)\n        mod->branch_veneer = (char *)mod->start + mod->branch_veneer_offset;\n\n    /* Transfer each section which specifies SHF_ALLOC */\n'''
if s.count(move_anchor) != 1:
    raise SystemExit(f'ERROR: module.c move anchor count={s.count(move_anchor)}')
s = s.replace(move_anchor, move_new, 1)
modc.write_text(s)

# 3) On CALL26/JUMP26 overflow emit a local 16-byte veneer:
#       ldr x16, #8
#       br  x16
#       .quad absolute_target
# A BL into the veneer preserves LR; BR transfers control without replacing it.
s = relo.read_text()
inc = '#include "insn.h"\n'
if s.count(inc) != 1:
    raise SystemExit(f'ERROR: relo include anchor count={s.count(inc)}')
s = s.replace(inc, inc + '#include "module.h"\n', 1)

apply_anchor = '''int apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,\n                   struct module *me)\n{\n'''
emitter = r'''#ifndef KPM_BRANCH_VENEER_SIZE
#define KPM_BRANCH_VENEER_SIZE 16U
#endif

static int emit_branch_veneer(struct module *me, u64 target, void **out)
{
    u8 *slot;

    if (!me || !out || !me->branch_veneer ||
        me->branch_veneer_used >= me->branch_veneer_count)
        return -ENOSPC;

    slot = (u8 *)me->branch_veneer +
           me->branch_veneer_used * KPM_BRANCH_VENEER_SIZE;
    me->branch_veneer_used++;

    /* AArch64: ldr x16, #8 ; br x16 ; .quad target */
    *(u32 *)(slot + 0) = 0x58000050U;
    *(u32 *)(slot + 4) = 0xd61f0200U;
    *(u64 *)(slot + 8) = target;
    *out = slot;
    return 0;
}

'''
if s.count(apply_anchor) != 1:
    raise SystemExit(f'ERROR: relo emitter anchor count={s.count(apply_anchor)}')
s = s.replace(apply_anchor, emitter + apply_anchor, 1)

branch_old = '''        case R_AARCH64_JUMP26:\n        case R_AARCH64_CALL26:\n            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, AARCH64_INSN_IMM_26);\n            break;\n'''
branch_new = '''        case R_AARCH64_JUMP26:\n        case R_AARCH64_CALL26:\n            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, AARCH64_INSN_IMM_26);\n            if (ovf == -ERANGE) {\n                void *veneer = 0;\n                int vrc = emit_branch_veneer(me, val, &veneer);\n                if (vrc) {\n                    pr_err("KPM far-branch veneer exhausted type=%llu target=%llx\\n",\n                           ELF64_R_TYPE(rel[i].r_info), val);\n                    return vrc;\n                }\n                ovf = reloc_insn_imm(RELOC_OP_PREL, loc, (u64)veneer, 2, 26,\n                                     AARCH64_INSN_IMM_26);\n                if (!ovf)\n                    pr_info("KPM_FAR_BRANCH_VENEER type=%llu loc=%llx target=%llx veneer=%llx\\n",\n                            ELF64_R_TYPE(rel[i].r_info), (u64)loc, val, (u64)veneer);\n            }\n            break;\n'''
if s.count(branch_old) != 1:
    raise SystemExit(f'ERROR: CALL26/JUMP26 anchor count={s.count(branch_old)}')
s = s.replace(branch_old, branch_new, 1)
relo.write_text(s)
PY

# Static source gates before invoking the compiler.
grep -q 'branch_veneer_count' "$SRC/kernel/patch/include/module.h" || fail 'veneer state missing'
grep -q 'count_branch_veneer_slots' "$SRC/kernel/patch/module/module.c" || fail 'veneer reservation missing'
grep -q 'KPM_FAR_BRANCH_VENEER' "$SRC/kernel/patch/module/relo.c" || fail 'far branch fallback missing'

echo '=== STATIC AARCH64 RANGE SELF-CHECK ==='
python3 - <<'PY'
# Reproduce the observed Nohello placement/target shape from runtime evidence.
module = 0xffffffc11fa00008
target = 0xffffffc080cd2698
veneer = 0xffffffc11faf0000
limit = 1 << 27
assert not (-limit <= target - module < limit), 'observed target unexpectedly fits CALL26'
assert -limit <= veneer - module < limit, 'local veneer unexpectedly outside CALL26 range'
# Literal-load veneer words: ldr x16,#8 ; br x16.
assert 0x58000050 == 0x58000000 | (2 << 5) | 16
assert 0xd61f0200 == 0xd61f0000 | (16 << 5)
print('KPM_FAR_BRANCH_RANGE_SELFTEST=PASS')
PY

echo '=== BUILD SUKISU KERNELPATCH ANDROID KPIMG ==='
(
  cd "$SRC/kernel"
  make clean >/dev/null 2>&1 || true
  export ANDROID=1
  export TARGET_COMPILE
  make -j"$(nproc)"
)

[[ -s "$SRC/kernel/kpimg" ]] || fail 'kpimg build output missing'
[[ -s "$SRC/kernel/kpimg.elf" ]] || fail 'kpimg.elf build output missing'
grep -aFq 'KPM_FAR_BRANCH_VENEER' "$SRC/kernel/kpimg" || fail 'veneer runtime marker missing from kpimg'

# Build Linux kptools so a later finalizer can inject this exact kpimg explicitly.
echo '=== BUILD KERNELPATCH KTOOLS ==='
(
  cd "$SRC/tools"
  rm -rf build
  mkdir build
  cd build
  cmake ..
  make -j"$(nproc)"
)
[[ -x "$SRC/tools/build/kptools" ]] || fail 'kptools build output missing'

cp "$SRC/kernel/kpimg" "$OUT/kpimg"
cp "$SRC/kernel/kpimg.elf" "$OUT/kpimg.elf"
cp "$SRC/tools/build/kptools" "$OUT/kptools-linux"
git -C "$SRC" diff -- kernel/patch/include/module.h kernel/patch/module/module.c kernel/patch/module/relo.c > "$OUT/farbranch.patch"

KPIMG_SHA="$(sha256sum "$OUT/kpimg" | awk '{print $1}')"
KPTOOLS_SHA="$(sha256sum "$OUT/kptools-linux" | awk '{print $1}')"
KP_VERSION="$($OUT/kptools-linux -v -k "$OUT/kpimg" 2>&1 || true)"

cat > "$OUT/proof.txt" <<EOF
KPM_FAR_BRANCH_BUILD=PASS
KERNELPATCH_SOURCE_REPO=$SRC_REPO
KERNELPATCH_SOURCE_REF=$SRC_REF
EXPECTED_VERSION_HEX=$EXPECTED_VERSION_HEX
KPIMG_SHA256=$KPIMG_SHA
KPTOOLS_SHA256=$KPTOOLS_SHA
KPM_FAR_BRANCH_VENEER_SIZE=16
KPM_FAR_BRANCH_TYPES=R_AARCH64_CALL26,R_AARCH64_JUMP26
KPM_FAR_BRANCH_RANGE_SELFTEST=PASS
KPM_VERSION_OUTPUT=$KP_VERSION
EOF

cat "$OUT/proof.txt"
echo 'PIXEL_KPM_FAR_BRANCH_PAYLOAD=PASS'

