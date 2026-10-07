#!/usr/bin/env python3
"""Compile/execute actual pinned event and SELinux integration fragments.

Host fixtures model policy ownership and locking; they do not qualify device
SELinux policy, boot events or a userspace/kernel UAPI match. Upstream GPL-2.0
continues to apply to the extracted source fragments.
"""
import argparse
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent

EVENT_FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define __user
#define __u32 uint32_t
#define DECLARE(type,name,val) enum { name=val }
#define pr_info(...) ((void)0)
static unsigned post_calls,boot_calls,mount_calls,sdcard_calls;
static unsigned copy_failure;
static unsigned copy_from_user(void *out,const void *in,unsigned size) {
 if (!in || copy_failure) {copy_failure=0;return size;}
 memcpy(out,in,size);return 0;
}
static void on_post_fs_data(void) {post_calls++;}
static void on_boot_completed(void) {boot_calls++;}
static void on_module_mounted(void) {mount_calls++;}
static void susfs_start_sdcard_monitor_fn(void) {sdcard_calls++;}
'''

EVENT_TEST = r'''
int main(void) {
 _Static_assert(KERNEL_SU_UAPI_VERSION==5,"qualified existing ABI3/4/5 declaration");
 _Static_assert(EVENT_POST_FS_DATA==1 && EVENT_BOOT_COMPLETED==2 &&
                EVENT_MODULE_MOUNTED==3 && EVENT_SERVICES==4,"event ABI mismatch");
 struct ksu_report_event_cmd event={EVENT_SERVICES};
 copy_failure=1;assert(do_report_event(&event)==-EFAULT);
 assert(do_report_event(&event)==1);assert(do_report_event(&event)==0);
 assert(!boot_calls && !mount_calls && !post_calls && !sdcard_calls);
 event.event=EVENT_MODULE_MOUNTED;assert(!do_report_event(&event));assert(mount_calls==1);
 event.event=EVENT_BOOT_COMPLETED;assert(!do_report_event(&event));assert(!do_report_event(&event));
 assert(boot_calls==1);
#ifdef CONFIG_KSU_SUSFS
 assert(sdcard_calls==1);
#else
 assert(sdcard_calls==0);
#endif
 event.event=EVENT_POST_FS_DATA;assert(!do_report_event(&event));assert(post_calls==1);
 event.event=EVENT_SERVICES;assert(do_report_event(&event)==1);assert(!do_report_event(&event));
 /* Repeated post-fs-data resets service deduplication for emulated soft reboot. */
 event.event=EVENT_POST_FS_DATA;assert(!do_report_event(&event));assert(post_calls==1);
 event.event=EVENT_SERVICES;assert(do_report_event(&event)==1);
 event.event=99;assert(!do_report_event(&event));
 assert(boot_calls==1 && mount_calls==1 && post_calls==1);
 return 0;
}
'''

POLICY_FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define GFP_KERNEL 0
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
struct policydb {int id;};
struct sidtab {int id;};
struct selinux_policy {struct policydb policydb;struct sidtab *sidtab;int latest_granting;};
static struct selinux_policy original={.policydb={1}},pool[8],*backup_sepolicy;
static struct sidtab backup_sidtab;
static struct {struct selinux_policy *policy;int policy_mutex;} selinux_state={&original,0};
static unsigned locked,unlock_calls,dup_calls,destroy_calls,sync_calls,rule_calls,flush_calls,susfs_calls;
static unsigned fail_dup_call,fail_sidtab,fail_isids;
static bool legacy_lock_present=true;
typedef int cpumask_t;
typedef int rwlock_t;
static cpumask_t cpu_mask;
static rwlock_t rw_lock;
static struct policydb legacy_db={1};
struct sched_param {int sched_priority;};
static struct task {void *mm;int policy,rt_priority;} task={&original,0,0},*current __attribute__((unused))=&task;
static int getenforce(void) {return 1;}
static void mutex_lock(int *mutex) {(void)mutex;assert(!locked);locked=1;}
static void mutex_unlock(int *mutex) {(void)mutex;assert(locked);locked=0;unlock_calls++;}
#define lockdep_is_held(mutex) (locked)
#define rcu_dereference_protected(ptr,condition) (assert(condition),(ptr))
#define rcu_assign_pointer(ptr,value) ((ptr)=(value))
static struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old) {
 assert(locked);dup_calls++;
 if (dup_calls==fail_dup_call) return (void *)(intptr_t)-ENOMEM;
 assert(dup_calls<=8);pool[dup_calls-1]=*old;return &pool[dup_calls-1];
}
static void *kzalloc(size_t size,int flags) {
 (void)flags;assert(size==sizeof(struct sidtab));return fail_sidtab?NULL:&backup_sidtab;
}
static int policydb_load_isids(struct policydb *db,struct sidtab *sidtab) {
 assert(db && sidtab);return fail_isids?-EINVAL:0;
}
static void kfree(void *ptr) {(void)ptr;}
static void ksu_destroy_sepolicy(struct selinux_policy *policy) {
 assert(policy);if (policy==&original) assert(sync_calls);destroy_calls++;
}
static int apply_kernelsu_rules_fn(void *ptr) {
 struct policydb *db=ptr;assert(db);db->id+=10;rule_calls++;return 0;
}
static void synchronize_rcu(void) {sync_calls++;}
static void reset_avc_cache(void) {flush_calls++;}
static void susfs_set_batch_sid(void) {susfs_calls++;}
static struct policydb *get_policydb(void) {return &legacy_db;}
static rwlock_t *ksu_get_policy_rwlock(void) {return legacy_lock_present?&rw_lock:NULL;}
static cpumask_t *ksu_get_current_cpumask_t(void) {return &cpu_mask;}
static void cpumask_copy(cpumask_t *out,const cpumask_t *in) {*out=*in;}
static int raw_smp_processor_id(void) {return 0;}
static cpumask_t *cpumask_of(int cpu) {(void)cpu;return &cpu_mask;}
static void set_cpus_allowed_ptr(struct task *p,const cpumask_t *mask) {(void)p;(void)mask;}
static void write_lock(rwlock_t *lock) {(void)lock;assert(!locked);locked=1;}
static void write_unlock(rwlock_t *lock) {(void)lock;assert(locked);locked=0;unlock_calls++;}
static void preempt_enable(void) {}
static void preempt_disable(void) {}
#define likely(value) (value)
static void sched_setscheduler_nocheck(struct task *p,int policy,const struct sched_param *param) {
 (void)p;(void)policy;(void)param;
}
static void stop_machine(int (*fn)(void *),void *arg,void *unused) {(void)unused;fn(arg);}
static void smp_mb(void) {}
'''

POLICY_TEST = r'''
static void reset(void) {
 original.policydb.id=1;selinux_state.policy=&original;backup_sepolicy=NULL;
 locked=unlock_calls=dup_calls=destroy_calls=sync_calls=rule_calls=flush_calls=susfs_calls=0;
 fail_dup_call=fail_sidtab=fail_isids=0;legacy_db.id=1;
}
int main(void) {
 reset();apply_kernelsu_rules();assert(!locked && rule_calls==1 && flush_calls==1);
#if LINUX_VERSION_CODE>=KERNEL_VERSION(5,10,0)
 assert(dup_calls==2 && unlock_calls==1 && sync_calls==1 && destroy_calls==1);
 assert(selinux_state.policy!=&original && selinux_state.policy->policydb.id==11);
 assert(original.policydb.id==1 && backup_sepolicy && backup_sepolicy->policydb.id==1);
#ifdef CONFIG_KSU_SUSFS
 assert(susfs_calls==1);
#else
 assert(!susfs_calls);
#endif
 reset();fail_dup_call=2;apply_kernelsu_rules();
 assert(!locked && unlock_calls==1 && selinux_state.policy==&original && !rule_calls && !flush_calls);
 reset();fail_sidtab=1;apply_kernelsu_rules();
 assert(!locked && !backup_sepolicy && rule_calls==1 && selinux_state.policy->policydb.id==11);
 reset();fail_isids=1;apply_kernelsu_rules();
 assert(!locked && !backup_sepolicy && rule_calls==1 && selinux_state.policy->policydb.id==11);
#else
 assert(!dup_calls && !sync_calls && !susfs_calls && legacy_db.id==11 && unlock_calls==1);
 reset();legacy_lock_present=false;apply_kernelsu_rules();
 assert(!locked && !unlock_calls && rule_calls==1 && flush_calls==1 && legacy_db.id==11);
#endif
 return 0;
}
'''

SCOPE_FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define __user
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,1,0)
#define KERNEL_SU_VERSION 40959
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#include "uapi/supercall.h"
#include "uapi/feature.h"
struct file {void *private_data;};
struct filename {int unused;};
static unsigned uid,handler_calls,copy_calls,install_calls;
static bool manager,allow_uid,copy_failure;
static bool is_manager(void) {return manager;}
static bool ksu_is_allow_uid_for_current(unsigned value) {(void)value;return allow_uid;}
static struct uid_value {unsigned val;} current_uid(void) {return (struct uid_value){uid};}
static unsigned copy_to_user(void *out,const void *in,unsigned size) {
 if (!out || copy_failure) {copy_failure=false;return size;}
 memcpy(out,in,size);copy_calls++;return 0;
}
static int ksu_install_su_fd(void) {install_calls++;return 9;}
'''

SCOPE_TEST = r'''
static bool contains(unsigned cmd,const unsigned *list,size_t length) {
 for(size_t i=0;i<length;i++) {
  if(cmd==list[i])return true;
 }
 return false;
}
int main(void) {
 _Static_assert(KERNEL_SU_UAPI_VERSION==5,"modern userspace must match");
 _Static_assert(KSU_GET_INFO_FLAG_BUNDLED==(1U<<4),"bundled bit ABI");
 struct ksu_get_info_cmd info={0};
 uid=20000;manager=false;assert(!do_get_info(&info));
 assert(info.uapi_version==5 && info.version==40959 && info.features==KSU_FEATURE_MAX && !info.flags);
 manager=true;assert(!do_get_info(&info));assert(info.flags==KSU_GET_INFO_FLAG_MANAGER);
 assert(!(info.flags&(KSU_GET_INFO_FLAG_LKM|KSU_GET_INFO_FLAG_BUNDLED)));
 copy_failure=true;assert(do_get_info(&info)==-EFAULT);
 assert(do_get_info(NULL)==-EFAULT);
 struct ksu_driver_context context={KSU_DRIVER_PERMISSION_SU_SESSION};
 struct file scoped={&context},plain={0};
 const unsigned public_cmds[]={KSU_IOCTL_GET_INFO,KSU_IOCTL_GET_INFO_LEGACY,KSU_IOCTL_CHECK_SAFEMODE,KSU_IOCTL_GET_FULL_VERSION};
 const unsigned root_only[]={KSU_IOCTL_REPORT_EVENT,KSU_IOCTL_SET_SEPOLICY,KSU_IOCTL_SET_INIT_PGRP,KSU_IOCTL_GET_SULOG_FD,KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT};
 const unsigned manager_only[]={KSU_IOCTL_GET_APP_PROFILE,KSU_IOCTL_SET_APP_PROFILE};
 for(unsigned role=0;role<3;role++)for(unsigned session=0;session<2;session++) {
  uid=role==0?0:20000;manager=role==1;allow_uid=role==0;
  const struct file *file=session?&scoped:&plain;
  unsigned n=0;
  for(unsigned i=0;ksu_ioctl_handlers[i].handler;i++,n++) {
   unsigned cmd=ksu_ioctl_handlers[i].cmd;
   bool expected;
   if(contains(cmd,public_cmds,sizeof(public_cmds)/sizeof(*public_cmds)))expected=true;
   else if(contains(cmd,manager_only,sizeof(manager_only)/sizeof(*manager_only)))expected=manager;
   else if(contains(cmd,root_only,sizeof(root_only)/sizeof(*root_only)))expected=uid==0;
   else if(cmd==KSU_IOCTL_GRANT_ROOT)expected=manager||allow_uid;
   else expected=uid==0||manager;
   if(session && (cmd==KSU_IOCTL_GET_WRAPPER_FD || cmd==KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT))expected=true;
   unsigned before=handler_calls+copy_calls;
   long ret=ksu_supercall_handle_ioctl(file,cmd,&info);
   if(expected) {assert(ret>=0);assert(handler_calls+copy_calls==before+1);}
   else {assert(ret==-EPERM);assert(handler_calls+copy_calls==before);}
  }
  assert(n==29);assert(ksu_supercall_handle_ioctl(file,0xffffffffU,&info)==-ENOTTY);
 }
 /* Successful exec installs the scoped descriptor; failed exec cannot install it. */
 int retval=-ENOENT;
 assert(!ksu_handle_post_execveat_sucompat(NULL,NULL,NULL,NULL,NULL,&retval));assert(!install_calls);
 retval=0;assert(!ksu_handle_post_execveat_sucompat(NULL,NULL,NULL,NULL,NULL,&retval));assert(install_calls==1);
 retval=1;assert(!ksu_handle_post_execveat_sucompat(NULL,NULL,NULL,NULL,NULL,&retval));assert(install_calls==2);
 return 0;
}
'''


def execute(temp, label, source, definitions, cc):
    cfile = temp / (label + '.c')
    binary = temp / label
    cfile.write_text(source)
    subprocess.run([cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-Wno-unused-parameter', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', *definitions, str(cfile), '-o', str(binary)], check=True)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    subprocess.run([str(binary)], check=True, env=env)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kernel', type=pathlib.Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('repair_integration', HERE / 'repair-sukisu-integration.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='sukisu-integration-test-') as directory:
        temp = pathlib.Path(directory)
        kernel = temp / 'kernel'
        for name in module.PINS:
            dest = kernel / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.kernel / name, dest)
        for name in ('include/uapi/app_profile.h', 'include/uapi/feature.h'):
            shutil.copyfile(args.kernel / name, kernel / name)
        module.repair(kernel)
        header = (kernel / 'include/uapi/supercall.h').read_text()
        enums = '\n'.join(re.findall(r'^DECLARE\(__u32, (?:EVENT_\w+|KERNEL_SU_UAPI_VERSION), \d+\);$', header, re.M))
        command = re.search(r'struct ksu_report_event_cmd \{.*?\n\};', header, re.S).group()
        dispatch = (kernel / 'supercall/dispatch.c').read_text()
        event = dispatch[dispatch.index('static int do_report_event('):dispatch.index('\nstatic int do_set_sepolicy(')]
        rules = (kernel / 'selinux/rules.c').read_text()
        policy = rules[rules.index('void apply_kernelsu_rules(void)'):rules.index('\n#define KSU_SEPOLICY_MAX_BATCH_SIZE')]
        for susfs in (False, True):
            definitions = ['-DCONFIG_KSU_SUSFS=1'] if susfs else []
            execute(temp, f'event-{int(susfs)}', EVENT_FIXTURE+enums+'\n'+command+event+EVENT_TEST,
                    definitions, args.cc)
            for version, name in ((0x060100, '6_1'), (0x041300, '4_19')):
                flags = definitions + [f'-DLINUX_VERSION_CODE={version}']
                if version >= 0x050a00:
                    flags.append('-DKSU_COMPAT_HAS_SELINUX_STATE=1')
                execute(temp, f'policy-{name}-{int(susfs)}', POLICY_FIXTURE+policy+POLICY_TEST,
                        flags, args.cc)
        info = dispatch[dispatch.index('static int do_get_info('):dispatch.index('\nstatic int do_get_info_legacy(')]
        table = dispatch[dispatch.index('static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[]'):dispatch.index('// clang-format on')]
        ioctl = dispatch[dispatch.index('long ksu_supercall_handle_ioctl('):dispatch.index('\nvoid __init ksu_supercall_dump_commands(')]
        mapping = (args.kernel / 'supercall/supercall.h').read_text()
        mapping = mapping[mapping.index('typedef int (*ksu_ioctl_handler_t)'):mapping.index('// Install KSU fd')]
        supercall = (args.kernel / 'supercall/supercall.c').read_text()
        context = supercall[:supercall.index('static int anon_ksu_release(')]
        session = supercall[supercall.index('bool ksu_is_su_session_fd('):supercall.index('\nstruct ksu_install_fd_tw')]
        perm = (args.kernel / 'supercall/perm.c').read_text()
        compat = (args.kernel / 'feature/sucompat.c').read_text()
        post_exec = compat[compat.index('int ksu_handle_post_execveat_sucompat('):compat.index('\n#ifdef KSU_COMPAT_USE_STATIC_KEY', compat.index('int ksu_handle_post_execveat_sucompat('))]
        handlers = sorted(set(re.findall(r'\.handler = (\w+)', table)) - {'NULL', 'do_get_info'})
        stubs = '\n'.join(f'static int {name}(void *arg) {{(void)arg;handler_calls++;return 37;}}' for name in handlers)
        execute(temp, 'scope-uapi5', SCOPE_FIXTURE+mapping+context+session+perm+info+stubs+table+ioctl+post_exec+SCOPE_TEST,
                ['-DCONFIG_KPM=1', '-DCONFIG_KSU_SUSFS=1', '-I'+str(kernel / 'include')], args.cc)
        print('SUKISU_BUILTIN_EVENT_AND_SELINUX_ASAN_UBSAN=PASS')
        print('SUKISU_UAPI5_GET_INFO_SCOPED_PERMISSIONS_POSTEXEC=PASS')


if __name__ == '__main__':
    main()
