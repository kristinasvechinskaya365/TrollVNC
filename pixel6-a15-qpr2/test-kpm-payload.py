#!/usr/bin/env python3
"""Execute repaired payload C functions with ASan/UBSan and realistic stubs.

The input clone is read only. A temporary copy is repaired, and actual C
function bodies are extracted from that copy instead of reimplemented here.
"""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def extract(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    return text[start:end]


PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

struct module {
    struct { const char *name, *version, *license, *author, *description; } info;
    char *args;
    unsigned int size, branch_veneer_offset, branch_veneer_count;
    int list;
    struct module *next;
};
static struct module modules, *first_module;
static int rcu_depth;
static void rcu_read_lock(void) { assert(rcu_depth == 0); ++rcu_depth; }
static void rcu_read_unlock(void) { assert(rcu_depth == 1); --rcu_depth; }
#define list_for_each_entry(pos, head, field) \
    for ((pos) = first_module; (pos); (pos) = (pos)->next)
static struct module *find_module(const char *name) {
    for (struct module *m = first_module; m; m = m->next)
        if (!strcmp(m->info.name, name)) return m;
    return NULL;
}
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
struct load_info { const Elf_Ehdr *hdr; Elf_Shdr *sechdrs; };
#define KPM_BRANCH_VENEER_SIZE 16U
#define logki(...) ((void)0)
typedef struct { uintptr_t arg0, arg1; int skip_origin; } hook_fargs3_t;
static int kpver = 3328;
static const char *build_time;
static const char *get_build_time(void) { return build_time; }
'''

TESTS = r'''
static void verify_result(char *buf, int capacity, int result, const char *expected) {
    assert(rcu_depth == 0);
    assert(memchr(buf, '\0', capacity));
    int needed = (int)strlen(expected) + 1;
    if (capacity >= needed) {
        assert(result == needed);
        assert(!strcmp(buf, expected));
        for (int i = 0; i < result; i++) assert((unsigned char)buf[i] != 0xa5);
    } else {
        assert(result == -ENOBUFS);
    }
}

static void test_formatting(void) {
    char one = 'X';
    assert(list_modules(NULL, 8) == -EINVAL);
    assert(list_modules(&one, 0) == -EINVAL && one == 'X');
    assert(list_modules(&one, -1) == -EINVAL && one == 'X');
    first_module = NULL;
    assert(list_modules(&one, 1) == 1 && one == '\0');
    assert(get_module_info(NULL, &one, 1) == -EINVAL);
    assert(get_module_info("", &one, 1) == -EINVAL);
    assert(get_module_info("absent", NULL, 1) == -EINVAL);
    assert(get_module_info("absent", &one, 0) == -EINVAL);
    assert(get_module_info("absent", &one, -1) == -EINVAL);
    assert(get_module_info("absent", &one, 1) == -ENOENT);
    assert(one == '\0' && rcu_depth == 0);

    struct module c = { .info = {.name="gamma"} };
    struct module b = { .info = {.name="beta"}, .next=&c };
    struct module a = { .info = {.name="alpha", .version="1", .license="GPL",
                       .author="A", .description="D"}, .args="x", .next=&b };
    first_module = &a;
    const char *names = "alpha\nbeta\ngamma";
    const char *info = "name=alpha\nversion=1\nlicense=GPL\nauthor=A\ndescription=D\nargs=x";
    for (int size = 1; size <= (int)strlen(info) + 3; size++) {
        char *buf = malloc(size);
        assert(buf);
        memset(buf, 0xa5, size);
        verify_result(buf, size, list_modules(buf, size), names);
        memset(buf, 0xa5, size);
        verify_result(buf, size, get_module_info("alpha", buf, size), info);
        free(buf);
    }

    const char *null_info = "name=beta\nversion=\nlicense=\nauthor=\ndescription=\nargs=";
    char normal[256];
    memset(normal, 0xa5, sizeof(normal));
    verify_result(normal, sizeof(normal), get_module_info("beta", normal, sizeof(normal)), null_info);
    assert(get_module_info("not-loaded", normal, sizeof(normal)) == -ENOENT);
    assert(rcu_depth == 0);

    char *long_text = malloc(32769);
    assert(long_text);
    memset(long_text, 'L', 32768);
    long_text[32768] = 0;
    a.info.description = long_text;
    for (int size = 1; size <= 256; size++) {
        char *buf = malloc(size);
        assert(buf);
        memset(buf, 0xa5, size);
        assert(get_module_info("alpha", buf, size) == -ENOBUFS);
        assert(memchr(buf, '\0', size) && rcu_depth == 0);
        free(buf);
    }
    a.info.name = long_text;
    for (int size = 1; size <= 256; size++) {
        char *buf = malloc(size);
        assert(buf);
        memset(buf, 0xa5, size);
        assert(list_modules(buf, size) == -ENOBUFS);
        assert(memchr(buf, '\0', size) && rcu_depth == 0);
        free(buf);
    }
    free(long_text);
    first_module = NULL;
}

static void test_version(void) {
    hook_fargs3_t args = {.arg0=0, .arg1=0};
    before_sukisu_kpm_version(&args, NULL);
    assert(args.skip_origin == 1);
    char one = 'X';
    args.arg0 = (uintptr_t)&one;
    args.arg1 = (uintptr_t)-1;
    args.skip_origin = 0;
    before_sukisu_kpm_version(&args, NULL);
    assert(one == 'X' && args.skip_origin == 1);
    args.arg1 = 0;
    before_sukisu_kpm_version(&args, NULL);
    assert(one == 'X');
    char long_time[1024];
    memset(long_time, 'T', sizeof(long_time) - 1);
    long_time[sizeof(long_time) - 1] = 0;
    build_time = long_time;
    for (int size = 1; size <= 256; size++) {
        char *buf = malloc(size);
        assert(buf);
        memset(buf, 0xa5, size);
        args.arg0 = (uintptr_t)buf;
        args.arg1 = size;
        before_sukisu_kpm_version(&args, NULL);
        assert(memchr(buf, '\0', size));
        assert(args.skip_origin == 1);
        free(buf);
    }
    build_time = NULL;
    char buf[32];
    args.arg0 = (uintptr_t)buf;
    args.arg1 = sizeof(buf);
    before_sukisu_kpm_version(&args, NULL);
    assert(!strcmp(buf, "3328 ()"));
}

static void test_veneer_arithmetic(void) {
    struct module m = {.size=0, .branch_veneer_count=0};
    assert(reserve_branch_veneers(&m) == 0 && m.size == 0);
    m.branch_veneer_count = 1;
    assert(reserve_branch_veneers(&m) == 0 && m.size == 16 && m.branch_veneer_offset == 0);
    m.size = 17;
    m.branch_veneer_count = 3;
    assert(reserve_branch_veneers(&m) == 0 && m.size == 80 && m.branch_veneer_offset == 32);
    m.size = UINT_MAX;
    m.branch_veneer_count = 1;
    assert(reserve_branch_veneers(&m) == -EOVERFLOW && m.size == UINT_MAX);
    m.size = UINT_MAX - 15;
    assert(reserve_branch_veneers(&m) == -EOVERFLOW && m.size == UINT_MAX - 15);
    m.size = UINT_MAX - 31;
    assert(reserve_branch_veneers(&m) == 0 && m.size == UINT_MAX - 15);
    m.size = 0;
    m.branch_veneer_count = UINT_MAX;
    assert(reserve_branch_veneers(&m) == -EOVERFLOW && m.size == 0);
    m.branch_veneer_count = UINT_MAX / KPM_BRANCH_VENEER_SIZE;
    assert(reserve_branch_veneers(&m) == 0 && m.size == UINT_MAX - 15);
    m.size = 16;
    assert(reserve_branch_veneers(&m) == -EOVERFLOW && m.size == 16);

    Elf_Ehdr header = {.e_shnum=6};
    Elf_Shdr sections[6] = {0};
    Elf64_Rela rel[] = {
        {.r_info=ELF64_R_INFO(0, R_AARCH64_CALL26)},
        {.r_info=ELF64_R_INFO(0, R_AARCH64_ABS64)},
        {.r_info=ELF64_R_INFO(0, R_AARCH64_JUMP26)},
    };
    sections[1].sh_type = SHT_RELA;
    sections[1].sh_info = 2;
    sections[1].sh_addr = (Elf64_Addr)(uintptr_t)rel;
    sections[1].sh_size = sizeof(rel);
    sections[2].sh_flags = SHF_ALLOC;
    sections[3] = sections[1];
    sections[3].sh_info = 4;  /* Nonallocated target: ignored. */
    sections[5] = sections[1];
    sections[5].sh_info = 99; /* Invalid target: ignored. */
    struct load_info input = {.hdr=&header, .sechdrs=sections};
    unsigned int count = UINT_MAX;
    assert(count_branch_veneer_slots(&input, &count) == 0 && count == 2);
    sections[1].sh_size = 0;
    assert(count_branch_veneer_slots(&input, &count) == 0 && count == 0);
}

int main(void) {
    (void)modules;
    test_formatting();
    test_version();
    test_veneer_arithmetic();
    puts("KPM_PAYLOAD_ASAN_UBSAN=PASS");
    return 0;
}
'''

BASELINE_TEST = r'''
int main(void) {
    char *long_text = malloc(32769);
    memset(long_text, 'L', 32768);
    long_text[32768] = 0;
    struct module victim = {.info={.name="victim", .version="1", .license="GPL",
                            .author="A", .description=long_text}, .args="x"};
    first_module = &victim;
    char *buf = malloc(256);
    get_module_info("victim", buf, 256);
    free(buf);
    free(long_text);
    return 0;
}
'''


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test-kpm-payload.py PINNED_PATCHED_KERNELPATCH_DIR")
    root = Path(sys.argv[1]).resolve()
    repair_file = Path(__file__).with_name("repair-kpm-payload.py")
    spec = importlib.util.spec_from_file_location("payload_repair", repair_file)
    assert spec and spec.loader
    repair = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(repair)
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != repair.SOURCE_REF:
        raise RuntimeError(f"KernelPatch source pin mismatch: {head}")
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="kpm-payload-safety-") as temporary:
        tmp = Path(temporary)
        clone = tmp / "source"
        paths = ("kernel/patch/module/module.c", "kernel/patch/sukisu/sukisu.c")
        for path in paths:
            dest = clone / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / path, dest)
        original_module = (clone / paths[0]).read_text()
        original_sukisu = (clone / paths[1]).read_text()
        # A later-file mismatch must leave the earlier file unchanged.
        (clone / paths[1]).write_text(original_sukisu.replace("buf_size-1", "buf_size - 1"))
        try:
            repair.repair(clone, check_git=False)
        except RuntimeError:
            pass
        else:
            raise AssertionError("source drift was accepted")
        assert (clone / paths[0]).read_text() == original_module
        (clone / paths[1]).write_text(original_sukisu)
        repair.repair(clone, check_git=False)
        module_text = (clone / paths[0]).read_text()
        sukisu_text = (clone / paths[1]).read_text()
        functions = [
            extract(module_text, "int list_modules("),
            extract(module_text, "int get_module_info("),
            extract(module_text, "static int count_branch_veneer_slots("),
            extract(module_text, "static int reserve_branch_veneers("),
            extract(sukisu_text, "void before_sukisu_kpm_version("),
        ]
        try:
            repair.repair(clone, check_git=False)
        except RuntimeError:
            pass
        else:
            raise AssertionError("already repaired source was accepted")
        harness = tmp / "payload-tests.c"
        harness.write_text(PREAMBLE + "\n\n".join(functions) + TESTS)
        binary = tmp / "payload-tests"
        compiler_flags = [
             cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-fsanitize=address,undefined",
             "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-no-pie",
        ]
        subprocess.run(
            compiler_flags + [str(harness), "-o", str(binary)], check=True
        )
        environment = os.environ.copy()
        # Work's process isolation blocks LeakSanitizer's /proc task inspection.
        # Address/undefined behavior instrumentation remains fully enabled.
        environment["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        subprocess.run([str(binary)], check=True, env=environment)
        # Confirm the same sanitizer setup detects the exact upstream defect.
        baseline = tmp / "upstream-overflow.c"
        baseline.write_text(PREAMBLE + extract(original_module, "int get_module_info(") + BASELINE_TEST)
        baseline_binary = tmp / "upstream-overflow"
        subprocess.run(
            compiler_flags + ["-Wno-unused-function", "-Wno-unused-variable",
                              str(baseline), "-o", str(baseline_binary)], check=True
        )
        control = subprocess.run([str(baseline_binary)], env=environment, capture_output=True, text=True)
        if control.returncode == 0 or "AddressSanitizer" not in control.stderr:
            raise AssertionError("upstream out-of-bounds negative control was not detected")
        print("KPM_UPSTREAM_OVERFLOW_NEGATIVE_CONTROL=PASS")
    print("KPM_PAYLOAD_EXACT_SOURCE_GATES=PASS")


if __name__ == "__main__":
    main()
