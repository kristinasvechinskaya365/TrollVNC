#!/usr/bin/env python3
"""Execute actual profile C predicates with host sanitizers; no device claims."""
import argparse
import json
import pathlib
import re
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('source', type=pathlib.Path)
p.add_argument('--system-map', type=pathlib.Path)
args=p.parse_args()
root=args.source


def function(text, name):
    m=re.search(r'^static (?:inline )?(?:bool|int) '+re.escape(name)+r'\(', text, re.M)
    assert m, name
    a=m.start();b=text.index('{',m.end());level=1;i=b+1
    while level:
        level += (text[i]=='{')-(text[i]=='}');i+=1
    return text[a:i]


source=(root/'kernel/kallsyms.c').read_text()
a=source.index('\t\tconst char *name = iter->name;')
b=source.index('\n\t\t\treturn 0;',a)
predicate=source[a:b]
assert predicate.rstrip().endswith('{')
predicate+='\nreturn true;\n}\nreturn false;\n'
helpers=['fake_state','fake_status','fake_status_initialize_key','backup_sepolicy',
         'initialize_fake_status','selinux_hide_mutex','my_sel_open_handle_status',
         'my_write_context','my_write_access','my_setprocattr',
         'selinux_hide_feature_get','selinux_hide_feature_set','selinux_hide_handler']
bridges=['sukisu_compact_find_symbol','sukisu_handle_kpm','sukisu_kpm_control',
         'sukisu_kpm_info','sukisu_kpm_list','sukisu_kpm_load_module_path',
         'sukisu_kpm_num','sukisu_kpm_unload_module','sukisu_kpm_version',
         'sukisu_super_access','sukisu_super_container_of','sukisu_super_find_struct']
prefixes=['','__cfi_','__pfx_','__ksymtab_','__kstrtab_','__kstrtabns_']
hidden={prefix+name+suffix for name in helpers+bridges
        for prefix in prefixes for suffix in ['', '.isra.0', '.constprop.2']}
controls=['schedule','__schedule','vfs_read','kallsyms_lookup_name',
          'selinux_status_update_setenforce','selnl_notify_setenforce',
          'fake_stateful','my_write_accessory','normal_fake_state','get_user_arg_ptr']
namespace=json.loads((pathlib.Path(__file__).parent/'symbol-namespace.json').read_text())
hidden.update(prefix+name+suffix for name in namespace.values()
              for prefix in prefixes for suffix in ['', '.isra.0', '.constprop.2'])
assert 'ksu_local_get_user_arg_ptr(' in (root/'drivers/kernelsu/runtime/ksud.c').read_text()
assert 'ksu_local_get_user_arg_ptr(' not in (root/'fs/exec.c').read_text()
assert '"file_wrapper: initialize anon_inode_mnt failed, got NULL\\n"' in (root/'drivers/kernelsu/infra/file_wrapper.c').read_text()
assert 'ksu_local_anon_inode_mnt' in (root/'drivers/kernelsu/infra/file_wrapper.c').read_text()
compiled=[]
if args.system_map:
    symbols=[line.split()[-1] for line in args.system_map.read_text().splitlines() if line.split()]
    # Audit every related compiled name, including explicit legacy helpers.
    needles=helpers+['sukisu_','ksu_','susfs_','kernelsu','on_post_fs_data',
                     'escape_to_root_for_init','is_zygote']
    compiled=[name for name in symbols if any(n in name for n in needles)]
    hidden.update(compiled)
    # Unique known root-owned names must no longer survive outside the namespace.
    for old in ['do_grant_root','do_enable_kpm','crown_manager','do_get_hook_type',
                'fake_state','fake_status','backup_sepolicy','my_setprocattr']:
        assert not any(n==old or n.startswith(old+'.') for n in symbols),('unprefixed root symbol',old)

bbg=(root/'security/baseband-guard/baseband_guard.c').read_text()
blk=(root/'security/baseband-guard/blkdev_helper.c').read_text()
partition_code=blk[blk.index('static bool partition_name_matches'):blk.index('#if LINUX_VERSION_CODE')]
bbg_header=(root/'security/baseband-guard/baseband_guard.h').read_text()
test_source=r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
static bool susfs_starts_with(const char *s,const char *prefix) {
    return strncmp(s,prefix,strlen(prefix))==0;
}
struct iterator { const char *name; };
static bool hidden_symbol(const char *value) {
    struct iterator item={value},*iter=&item;
''' + predicate + '\n}\n' + bbg_header + '\n' + partition_code + r'''
static int forced_result;
static int get_cmdline(void *task,char *buf,int size) {
    (void)task;
    if(forced_result>0) memset(buf,'x',(size_t)size);
    return forced_result;
}
#define current NULL
''' + function(bbg,'bbg_get_cmdline') + r'''
int main(void) {
''' + ''.join('assert(hidden_symbol('+json.dumps(name)+'));\n' for name in sorted(hidden)) + ''.join(
    'assert(!hidden_symbol('+json.dumps(name)+'));\n' for name in controls) + r'''
    assert(partition_name_in_allowlist("boot_a",64));
    assert(partition_name_in_allowlist("boot_b",64));
    assert(partition_name_in_allowlist("vendor_boot_b",64));
    assert(partition_name_in_allowlist("init_boot_a",64));
    assert(partition_name_in_allowlist("userdata",64));
    assert(partition_name_in_allowlist("recovery_b",64));
    assert(!partition_name_in_allowlist("bootloader_a",64));
    assert(!partition_name_in_allowlist("modem_a",64));
    assert(!partition_name_in_allowlist("radio_b",64));
    assert(!partition_name_in_allowlist("persist",64));
    assert(!partition_name_in_allowlist("boot_a_suffix",64));
    assert(!partition_name_in_allowlist(NULL,64));
    assert(!partition_name_in_allowlist("",64));
    assert(!partition_name_in_allowlist("boot",0));
    const char unterminated[4]={'b','o','o','t'};
    assert(!partition_name_in_allowlist(unterminated,sizeof(unterminated)));
    char buf[8];
    memset(buf,0x55,sizeof(buf));forced_result=0;
    assert(bbg_get_cmdline(buf,sizeof(buf))==0 && buf[0]==0);
    memset(buf,0x55,sizeof(buf));forced_result=-1;
    assert(bbg_get_cmdline(buf,sizeof(buf))==0 && buf[0]==0);
    forced_result=sizeof(buf);
    assert(bbg_get_cmdline(buf,sizeof(buf))==sizeof(buf) && buf[7]==0);
    forced_result=4;
    assert(bbg_get_cmdline(buf,sizeof(buf))==4 && buf[4]==0);
    assert(bbg_get_cmdline(NULL,sizeof(buf))==0);
    assert(bbg_get_cmdline(buf,0)==0);
    puts("PROFILE_ACTUAL_C_ASAN_UBSAN=PASS");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='pixel6-profile-') as td:
    path=pathlib.Path(td)
    (path/'test.c').write_text(test_source)
    subprocess.run(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                    '-fno-pie','-no-pie',str(path/'test.c'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)

# Source restrictions are checked again from actual Image config by verify.py.
assert '.name = "vmlinux", .mode = 0400,' in (root/'kernel/bpf/sysfs_btf.c').read_text()
assert 'int kptr_restrict __read_mostly = 2;' in (root/'lib/vsprintf.c').read_text()
assert 'DEFINE_STATIC_KEY_FALSE(susfs_is_log_enabled);' in (root/'fs/susfs.c').read_text()
assert 'allow_has(' not in bbg and 'allow_add(' not in bbg
print(json.dumps({'synthetic_and_compiled_hidden_names':len(hidden),
                  'compiled_names_tested':len(compiled),'ordinary_controls':len(controls),
                  'BBG_partition_boundaries':'PASS','BBG_empty_cmdline':'PASS',
                  'physical_runtime':'NOT_TESTED'},sort_keys=True))
