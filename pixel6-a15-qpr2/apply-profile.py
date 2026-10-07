#!/usr/bin/env python3
"""Apply the reviewed Pixel 6 profile to the pinned, integrated source tree."""
import hashlib
import json
import pathlib
import shutil
import sys

root, bbg, out = map(pathlib.Path, sys.argv[1:])
changes = []


def replace(path, old, new, count=1):
    p = root / path
    text = p.read_text()
    assert text.count(old) == count, (path, old, text.count(old))
    p.write_text(text.replace(old, new))
    changes.append(path)


# Keep IKCONFIG in Image for reproducible verification, without its proc file.
replace('arch/arm64/configs/gki_defconfig', 'CONFIG_IKCONFIG_PROC=y\n', '')
# Upstream's default is y; omitting the explicit n retains canonical defconfig.
replace('arch/arm64/configs/gki_defconfig', '# CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set\n', '')
replace('arch/arm64/configs/gki_defconfig', 'CONFIG_SECURITY=y\n',
        'CONFIG_SECURITY_DMESG_RESTRICT=y\nCONFIG_SECURITY=y\n')
replace('arch/arm64/configs/gki_defconfig', 'CONFIG_MAGIC_SYSRQ=y\n',
        'CONFIG_MAGIC_SYSRQ=y\nCONFIG_DEBUG_FS_DISALLOW_MOUNT=y\n')

# Keep BTF and Android's BPF support. Limit the raw type/symbol file to root.
replace('kernel/bpf/sysfs_btf.c', '.name = "vmlinux", .mode = 0444,',
        '.name = "vmlinux", .mode = 0400,')
# Avoid exposing raw symbol addresses before Android applies its sysctl policy.
# The root administrator can still change this standard sysctl if necessary.
replace('lib/vsprintf.c', 'int kptr_restrict __read_mostly;',
        'int kptr_restrict __read_mostly = 2;')

# Preserve all nine SUSFS capabilities, with opt-in diagnostic logging.
replace('fs/susfs.c', 'DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled);',
        'DEFINE_STATIC_KEY_FALSE(susfs_is_log_enabled);')
replace('fs/susfs.c', 'static_branch_likely(&susfs_is_log_enabled)',
        'static_branch_unlikely(&susfs_is_log_enabled)', count=2)

# SukiSU is a unity object: scope this change to that object, retain errors,
# warnings and its separate root-access audit feature.
replace('drivers/kernelsu/include/klog.h', '\n#endif\n\n#endif\n',
        '\n#endif\n\n#ifndef CONFIG_KSU_DEBUG\n#undef pr_info\n'
        '#define pr_info pr_debug\n#endif\n\n#endif\n')

# Record the modified source in provenance rather than an incidental worktree
# suffix. This retains the actual base revision; no Google build ID is invented.
replace('scripts/setlocalversion', "printf '%s' -dirty",
        ': # Reviewed patch set is recorded in profile-source-sha256.json')

# Cover the unprefixed helper symbols introduced by the SELinux wrappers.
# Exact names plus compiler suffixes are matched; ordinary kernel names remain.
anchor = '\t\t\tstrstr(iter->name, "kernelsu") ||\n'
names = ['fake_state', 'fake_status', 'fake_status_initialize_key',
         'backup_sepolicy', 'initialize_fake_status', 'selinux_hide_mutex',
         'my_sel_open_handle_status', 'my_write_context', 'my_write_access',
         'my_setprocattr', 'selinux_hide_feature_get', 'selinux_hide_feature_set',
         'selinux_hide_handler']
checks = ''.join('\t\t\t(!strcmp(name, "' + n + '") ||\n'
                 '\t\t\t susfs_starts_with(name, "' + n + '.")) ||\n'
                 for n in names)
replace('kernel/kallsyms.c', anchor, anchor + checks)
prefixes = ['__kstrtabns_', '__ksymtab_', '__kstrtab_', '__cfi_', '__pfx_']
normalize = '\t\tconst char *name = iter->name;\n'
for i, prefix in enumerate(prefixes):
    normalize += ('\t\t' + ('if' if i == 0 else 'else if') +
                  ' (susfs_starts_with(name, "' + prefix + '"))\n' +
                  '\t\t\tname += ' + str(len(prefix)) + ';\n')
replace('kernel/kallsyms.c', '\t{\n\t\tif (strstr(iter->name, "sukisu_")',
        '\t{\n' + normalize + '\t\tif (strstr(iter->name, "sukisu_")')

# BBG is a partition-write guard, not a root-hiding or attestation mechanism.
dest = root / 'security/baseband-guard'
assert not dest.exists(), dest
files = ['Kconfig', 'LICENSE', 'baseband_guard.c', 'baseband_guard.h',
         'blkdev_helper.c', 'blkdev_helper.h', 'kernel_compat.h',
         'tracing/tracing.c', 'tracing/tracing.h', 'tracing/kernel_compat.h']
for name in files:
    p = dest / name
    p.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bbg / name, p)
replace('security/baseband-guard/Kconfig', 'depends on SECURITY\n',
        'depends on SECURITY && SECURITY_SELINUX\n')

# The upstream device-number allow cache has no synchronization or removal,
# and can retain authorization across device-number reuse. Resolve each check.
p = dest / 'baseband_guard.c'
s = p.read_text()
a = s.index('struct device_hash_node ')
b = s.index('static bool is_zram_device', a)
s = s[:a] + s[b:]
s = s.replace('\t\tallow_add(cur);\n', '')
assert s.count('allow_has(inode->i_rdev) || ')==3
s = s.replace('allow_has(inode->i_rdev) || ', '')
s = s.replace('reverse_allow_match_and_cache', 'resolve_allowed_device')
old='\tif (!buf || buflen <= 0) return 0;\n\tn = get_cmdline'
assert s.count(old)==1
s = s.replace(old, '\tif (!buf || buflen <= 0) return 0;\n\tbuf[0] = \'\\0\';\n\n\tn = get_cmdline')
p.write_text(s)

# Boot/recovery guard options apply to both slots. A bootconfig-only slot
# declaration must not silently change which allowlisted partitions work.
p=dest/'blkdev_helper.c'
s=p.read_text()
a=s.index('extern char *saved_command_line;')
b=s.index('static bool partition_name_matches', a)
s=s[:a]+s[b:]
s=s.replace('\tconst char *slot_suffix = slot_suffix_from_cmdline();\n', '')
a=s.index('\t\tif (slot_suffix) {')
b=s.index('\n\t\tif (partition_name_matches(name, name_len,', a)
s=s[:a]+s[b:]
p.write_text(s)

# No shell-time network lookups, generated-header races, or floating versions.
# Generate private SELinux headers with the kernel's already-built host tool.
(dest / 'Makefile').write_text('''# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_BBG) += bbg.o
bbg-y := baseband_guard.o tracing/tracing.o blkdev_helper.o
ccflags-y += -I$(obj) -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include -I$(srctree)/block
ccflags-y += -DBBG_USE_DEFINE_LSM -DBB_HAS_SELINUX_STATE -DBB_HAS_IOCTL_COMPAT
ccflags-y += -DBBG_VERSION=\\"a54e0dc6\\" -DBBG_REPO=\\"vc-teahouse/Baseband-guard\\"
$(addprefix $(obj)/,$(bbg-y)): $(obj)/flask.h
quiet_cmd_bbg_flask = GEN     $(obj)/flask.h $(obj)/av_permissions.h
      cmd_bbg_flask = $< $(obj)/flask.h $(obj)/av_permissions.h
targets += flask.h av_permissions.h
$(obj)/flask.h: scripts/selinux/genheaders/genheaders FORCE
\t$(call if_changed,bbg_flask)
''')
assert 'LSM_HOOK(int, 0, file_ioctl_compat,' in (root/'include/linux/lsm_hook_defs.h').read_text()
assert '#define DEFINE_LSM(lsm)' in (root/'include/linux/lsm_hooks.h').read_text()
p = root/'security/Makefile'
p.write_text(p.read_text()+'\nobj-$(CONFIG_BBG) += baseband-guard/\n')
p = root/'security/Kconfig'
s=p.read_text()
anchor='source "security/selinux/Kconfig"\n'
assert s.count(anchor)==1
s=s.replace(anchor, anchor+'source "security/baseband-guard/Kconfig"\n')
old='default "landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"'
assert s.count(old)==1
s=s.replace(old, old[:-1]+',baseband_guard"')
p.write_text(s)

paths=sorted(set(changes+['security/Makefile','security/Kconfig']) |
             {str(p.relative_to(root)) for p in dest.rglob('*') if p.is_file()})
proof={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}
out.mkdir(parents=True, exist_ok=True)
(out/'profile-source-sha256.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'profile-symbol-names.json').write_text(json.dumps(names,indent=2)+'\n')
print('PIXEL6_PROFILE_SOURCE=PASS')
