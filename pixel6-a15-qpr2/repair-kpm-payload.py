#!/usr/bin/env python3
"""Repair bounded payload defects after the exact pinned far-branch patch.

These replacements intentionally fail on source drift. They do not change the
KPM command ABI: successful text results include their final NUL in the count;
incomplete output and invalid arguments return a negative errno.
"""

from pathlib import Path
import subprocess
import sys

SOURCE_REF = "e565c93ff6d0b992d9dfcbd43533a49d744a5f23"

LIST_OLD = r'''int list_modules(char *out_names, int size)
{
    rcu_read_lock();

    struct module *pos;
    int off = 0;
    list_for_each_entry(pos, &modules.list, list)
    {
        off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
    }
    if (off > 0) out_names[off - 1] = '\0';

    rcu_read_unlock();
    return off;
}'''

LIST_NEW = r'''int list_modules(char *out_names, int size)
{
    struct module *pos;
    int off = 0, rc = 1;

    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';
    rcu_read_lock();

    list_for_each_entry(pos, &modules.list, list)
    {
        int available = size - off;
        int written = snprintf(out_names + off, available, "%s%s",
                               off ? "\n" : "", pos->info.name ?: "");
        if (written < 0) {
            rc = written;
            goto out;
        }
        if (written >= available) {
            rc = -ENOBUFS;
            goto out;
        }
        off += written;
        rc = off + 1;
    }
out:
    rcu_read_unlock();
    return rc;
}'''

INFO_OLD = r'''int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) return -ENOENT;

    int sz = snprintf(out_info, size - 1,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args);

    if (sz > 0) out_info[sz - 1] = '\0';
    // logkfd("%s", out_info);

    rcu_read_unlock();
    return sz;
}'''

INFO_NEW = r'''int get_module_info(const char *name, char *out_info, int size)
{
    struct module *mod;
    int sz, rc;

    if (!name || !*name || !out_info || size <= 0) return -EINVAL;
    out_info[0] = '\0';
    rcu_read_lock();
    mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    sz = snprintf(out_info, size,
                  "name=%s\n"
                  "version=%s\n"
                  "license=%s\n"
                  "author=%s\n"
                  "description=%s\n"
                  "args=%s",
                  mod->info.name ?: "", mod->info.version ?: "",
                  mod->info.license ?: "", mod->info.author ?: "",
                  mod->info.description ?: "", mod->args ?: "");
    if (sz < 0) rc = sz;
    else if (sz >= size) rc = -ENOBUFS;
    else rc = sz + 1;
out:
    rcu_read_unlock();
    return rc;
}'''

VERSION_OLD = r'''void before_sukisu_kpm_version(hook_fargs3_t* args, void* udata) {
    char * buf = (char *) args->arg0;
    int buf_size =  (int) args->arg1;
    const char *buildtime = get_build_time();

    snprintf(buf, buf_size-1, "%d (%s)", kpver, buildtime);
    args->skip_origin = 1;
}'''

VERSION_NEW = r'''void before_sukisu_kpm_version(hook_fargs3_t* args, void* udata) {
    char * buf = (char *) args->arg0;
    int buf_size =  (int) args->arg1;
    const char *buildtime = get_build_time();

    if (buf && buf_size > 0)
        snprintf(buf, buf_size, "%d (%s)", kpver, buildtime ?: "");
    args->skip_origin = 1;
}'''

COUNT_OLD = r'''static unsigned int count_branch_veneer_slots(const struct load_info *info)
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
}'''

COUNT_NEW = r'''static int count_branch_veneer_slots(const struct load_info *info,
                                     unsigned int *out_count)
{
    unsigned int i, count = 0;
    unsigned long j;

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
            if (type == R_AARCH64_CALL26 || type == R_AARCH64_JUMP26) {
                if (count == (~0U / KPM_BRANCH_VENEER_SIZE))
                    return -EOVERFLOW;
                count++;
            }
        }
    }
    *out_count = count;
    return 0;
}

static int reserve_branch_veneers(struct module *mod)
{
    unsigned long offset, bytes;

    if (!mod->branch_veneer_count) return 0;
    offset = ((unsigned long)mod->size + 15UL) & ~15UL;
    bytes = (unsigned long)mod->branch_veneer_count * KPM_BRANCH_VENEER_SIZE;
    if (offset > ~0U || bytes > ~0U - offset) return -EOVERFLOW;
    mod->branch_veneer_offset = (unsigned int)offset;
    mod->size = (unsigned int)(offset + bytes);
    logki("KPM branch veneer reserve: slots=%u offset=%x total=%x\n",
          mod->branch_veneer_count, mod->branch_veneer_offset, mod->size);
    return 0;
}'''

LAYOUT_OLD = r'''    mod->branch_veneer_count = count_branch_veneer_slots(info);
    if (mod->branch_veneer_count) {
        mod->branch_veneer_offset = ALIGN(mod->size, 16);
        mod->size = mod->branch_veneer_offset +
                    mod->branch_veneer_count * KPM_BRANCH_VENEER_SIZE;
        logki("KPM branch veneer reserve: slots=%u offset=%x total=%x\n",
              mod->branch_veneer_count, mod->branch_veneer_offset, mod->size);
    }'''

LAYOUT_NEW = r'''    if ((rc = count_branch_veneer_slots(info, &mod->branch_veneer_count))) goto free;
    if ((rc = reserve_branch_veneers(mod))) goto free;'''


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: exact source anchor count {count}, expected 1")
    return text.replace(old, new, 1)


def repair(root: Path, *, check_git: bool = True) -> None:
    if check_git:
        head = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
        if head != SOURCE_REF:
            raise RuntimeError(f"KernelPatch pin mismatch: {head}")
    module = root / "kernel/patch/module/module.c"
    sukisu = root / "kernel/patch/sukisu/sukisu.c"
    module_text = module.read_text()
    for label, old, new in (
        ("list_modules", LIST_OLD, LIST_NEW),
        ("get_module_info", INFO_OLD, INFO_NEW),
        ("count/reserve veneers", COUNT_OLD, COUNT_NEW),
        ("reserve veneer call", LAYOUT_OLD, LAYOUT_NEW),
    ):
        module_text = replace_once(module_text, old, new, label)
    sukisu_text = replace_once(
        sukisu.read_text(), VERSION_OLD, VERSION_NEW, "version formatting"
    )
    # Validate every preimage before any write, so source drift has no partial effect.
    module.write_text(module_text)
    sukisu.write_text(sukisu_text)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: repair-kpm-payload.py PINNED_PATCHED_KERNELPATCH_DIR")
    repair(Path(sys.argv[1]).resolve())
    print("KPM_PAYLOAD_BOUNDS_REPAIR=PASS")
