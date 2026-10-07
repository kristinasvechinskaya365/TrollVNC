#!/usr/bin/env python3
"""Execute the repaired, actual pinned C handlers with ASan/UBSan usercopy stubs.

This is a host bounds/ABI regression test, not a device KPM runtime test.
Repaired upstream fragments retain their GPL-2.0-or-later licensing.
"""
import argparse
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent

PREFIX = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define __user
#define noinline __attribute__((noinline))
#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024
#define SUKISU_KPM_LOAD 1
#define SUKISU_KPM_UNLOAD 2
#define SUKISU_KPM_NUM 3
#define SUKISU_KPM_LIST 4
#define SUKISU_KPM_INFO 5
#define SUKISU_KPM_CONTROL 6
#define SUKISU_KPM_VERSION 7
struct ksu_kpm_cmd { uint64_t control_code, arg1, arg2, result_code; };
struct user_area { uintptr_t base; size_t size; };
static struct user_area areas[16];
static unsigned areas_n;
static unsigned method_calls, data_copies;
static int payload_mode, fail_next_copy;
static void *result_ptr;
static void reg_user(void *p, size_t size) {
    assert(areas_n < 16);
    areas[areas_n++] = (struct user_area){ (uintptr_t)p, size };
}
static bool access_ok(const void *p, size_t size) {
    uintptr_t a=(uintptr_t)p;
    if (!p) return false;
    for (unsigned i=0;i<areas_n;i++) {
        if (a>=areas[i].base && a-areas[i].base<=areas[i].size &&
            size<=areas[i].size-(a-areas[i].base)) return true;
    }
    return false;
}
static size_t copy_from_user(void *out,const void *in,size_t size) {
    if (!access_ok(in,size)) return size ? size : 1;
    memcpy(out,in,size); return 0;
}
static size_t copy_to_user(void *out,const void *in,size_t size) {
    if (fail_next_copy) { fail_next_copy=0; return size ? size : 1; }
    if (!access_ok(out,size)) return size ? size : 1;
    if (out!=result_ptr) data_copies++;
    memcpy(out,in,size); return 0;
}
static long strncpy_from_user(char *out,const char *in,long size) {
    if (!access_ok(in,(size_t)size)) return -EFAULT;
    for (long i=0;i<size;i++) { out[i]=in[i]; if (!in[i]) return i; }
    return size;
}
static void sukisu_kpm_load_module_path(const char *path,const char *args,void *ptr,int *res) {
    (void)ptr; method_calls++;
    assert(!strcmp(path,"/data/test.kpm")); assert(!strcmp(args,""));
    if (!payload_mode) *res=0;
}
static void sukisu_kpm_unload_module(const char *name,void *ptr,int *res) {
    (void)ptr; method_calls++; assert(!strcmp(name,"test"));
    if (!payload_mode) *res=0;
}
static void sukisu_kpm_num(int *res) {
    method_calls++; if (!payload_mode) *res=2;
}
static void sukisu_kpm_info(const char *name,char *buf,int size,int *res) {
    method_calls++; assert(size==256);
    if (payload_mode==1) return;
    if (payload_mode==2) { *res=size+1; return; }
    if (!strcmp(name,"missing")) { *res=-ENOENT; return; }
    if (!strcmp(name,"full")) { memset(buf,'I',size); buf[size-1]=0; *res=size; return; }
    memcpy(buf,"info",5); *res=5;
}
static void sukisu_kpm_list(void *out,int size,int *res) {
    method_calls++; assert(size>0 && size<=1024);
    if (payload_mode==1) return;
    if (payload_mode==2) { *res=size+1; return; }
    if (size<5) { *res=-ENOBUFS; return; }
    memcpy(out,"test",5); *res=5;
}
static void sukisu_kpm_control(const char *name,const char *args,long len,int *res) {
    method_calls++; assert(!strcmp(name,"test")); assert(!strcmp(args,"hello"));
    assert(len==5); if (!payload_mode) *res=17;
}
static void sukisu_kpm_version(char *buf,int size) {
    method_calls++; assert(size==256);
    if (payload_mode==1) return;
    if (payload_mode==2) { memset(buf,'V',size); return; }
    memcpy(buf,"0.13.0",7);
}
struct DynamicStructMember { const char *name; size_t size, offset; };
struct DynamicStructInfo { const char *name; size_t count,total_size; struct DynamicStructMember *members; };
static struct DynamicStructMember alpha_m[]={{"x",1,7},{"y",2,19},{"z",8,47}};
static struct DynamicStructMember beta_m[]={{"x",3,101},{"y",4,107},{"z",5,119},{"w",6,137}};
static struct DynamicStructMember gamma_m[]={{"x",9,257}};
static struct DynamicStructInfo alpha={"alpha",3,64,alpha_m};
static struct DynamicStructInfo beta={"beta",4,160,beta_m};
static struct DynamicStructInfo gamma={"gamma",1,512,gamma_m};
static struct DynamicStructInfo *dynamic_struct_infos[]={&alpha,&beta,&gamma};
'''

TESTS = r'''
int main(void) {
    char path[256]={0}, name[256]={0}, args[1024]={0}, out[2048];
    int res=0;
    struct ksu_kpm_cmd cmd={0};
    reg_user(path,sizeof(path)); reg_user(name,sizeof(name)); reg_user(args,sizeof(args));
    reg_user(out,sizeof(out)); reg_user(&res,sizeof(res)); reg_user(&cmd,sizeof(cmd));
    result_ptr=&res; strcpy(path,"/data/test.kpm"); strcpy(name,"test"); strcpy(args,"hello");
#define RUN(C,A,B) do { res=123456; assert(!sukisu_handle_kpm((C),(uintptr_t)(A),(uintptr_t)(B),(uintptr_t)&res)); } while(0)
    /* Numeric control commands reach the real handler; invalid commands do not. */
    cmd=(struct ksu_kpm_cmd){SUKISU_KPM_NUM,0,0,(uintptr_t)&res};
    assert(!do_kpm(&cmd) && res==2);
    unsigned calls=method_calls;
    cmd.control_code=0; assert(do_kpm(&cmd)==-EINVAL);
    cmd.control_code=8; assert(do_kpm(&cmd)==-EINVAL);
    cmd.control_code=UINT64_MAX; assert(do_kpm(&cmd)==-EINVAL);
    assert(method_calls==calls);
    cmd.control_code=SUKISU_KPM_NUM; cmd.result_code=0; assert(do_kpm(&cmd)==-EFAULT);
    assert(do_kpm(NULL)==-EFAULT);
    RUN(8,0,0); assert(res==-EINVAL && method_calls==calls);
    /* LOAD supports absent args without exposing an uninitialized stack string. */
    RUN(SUKISU_KPM_LOAD,path,0); assert(res==0);
    RUN(SUKISU_KPM_UNLOAD,name,0); assert(res==0);
    memset(path,'X',sizeof(path)); calls=method_calls;
    RUN(SUKISU_KPM_LOAD,path,0); assert(res==-ENAMETOOLONG && method_calls==calls);
    path[0]=0; RUN(SUKISU_KPM_LOAD,path,0); assert(res==-EINVAL);
    RUN(SUKISU_KPM_LOAD,0,0); assert(res==-EFAULT);
    /* INFO propagates missing-module errors and copies only initialized extent. */
    memset(out,0x5a,sizeof(out)); RUN(SUKISU_KPM_INFO,name,out);
    assert(res==0 && !memcmp(out,"info",5) && (unsigned char)out[5]==0x5a);
    strcpy(name,"missing"); unsigned copies=data_copies;
    RUN(SUKISU_KPM_INFO,name,out); assert(res==-ENOENT && data_copies==copies);
    strcpy(name,"full"); RUN(SUKISU_KPM_INFO,name,out);
    assert(res==0 && out[255]==0 && (unsigned char)out[256]==0x5a);
    strcpy(name,"test"); payload_mode=2;
    RUN(SUKISU_KPM_INFO,name,out); assert(res==-ENOBUFS);
    payload_mode=1; RUN(SUKISU_KPM_INFO,name,out); assert(res==-EOPNOTSUPP);
    payload_mode=0; RUN(SUKISU_KPM_INFO,name,0); assert(res==-EFAULT);
    /* LIST treats arg2 as capacity and clamps the actual local payload buffer. */
    calls=method_calls; copies=data_copies;
    RUN(SUKISU_KPM_LIST,out,0); assert(res==-EINVAL);
    RUN(SUKISU_KPM_LIST,0,1024); assert(res==-EFAULT);
    assert(method_calls==calls && data_copies==copies);
    memset(out,0x5a,sizeof(out)); RUN(SUKISU_KPM_LIST,out,1024);
    assert(res==5 && !memcmp(out,"test",5) && (unsigned char)out[5]==0x5a);
    RUN(SUKISU_KPM_LIST,out,1025); assert(res==5 && (unsigned char)out[5]==0x5a);
    RUN(SUKISU_KPM_LIST,out,4096); assert(res==5 && (unsigned char)out[5]==0x5a);
    RUN(SUKISU_KPM_LIST,out,UINT64_MAX); assert(res==5 && (unsigned char)out[5]==0x5a);
    RUN(SUKISU_KPM_LIST,out,1); assert(res==-ENOBUFS);
    payload_mode=2; RUN(SUKISU_KPM_LIST,out,1024); assert(res==-ENOBUFS);
    payload_mode=1; RUN(SUKISU_KPM_LIST,out,1024); assert(res==-EOPNOTSUPP);
    payload_mode=0;
    /* CONTROL requires terminated names/args and preserves argument length. */
    RUN(SUKISU_KPM_CONTROL,name,args); assert(res==17);
    memset(name,'X',32); calls=method_calls;
    RUN(SUKISU_KPM_CONTROL,name,args); assert(res==-ENAMETOOLONG && method_calls==calls);
    strcpy(name,"test"); memset(args,'X',sizeof(args));
    RUN(SUKISU_KPM_CONTROL,name,args); assert(res==-ENAMETOOLONG);
    RUN(SUKISU_KPM_CONTROL,name,0); assert(res==-EFAULT);
    /* VERSION handles zero, one, small, normal and huge caller capacities. */
    RUN(SUKISU_KPM_VERSION,out,0); assert(res==-EINVAL);
    memset(out,0x5a,sizeof(out)); RUN(SUKISU_KPM_VERSION,out,1);
    assert(res==0 && out[0]==0 && (unsigned char)out[1]==0x5a);
    RUN(SUKISU_KPM_VERSION,out,4); assert(res==0 && !memcmp(out,"0.1",4));
    RUN(SUKISU_KPM_VERSION,out,256); assert(res==0 && !strcmp(out,"0.13.0"));
    RUN(SUKISU_KPM_VERSION,out,UINT64_MAX); assert(res==0 && !strcmp(out,"0.13.0"));
    payload_mode=1; RUN(SUKISU_KPM_VERSION,out,256); assert(res==-EOPNOTSUPP);
    payload_mode=2; RUN(SUKISU_KPM_VERSION,out,256); assert(res==-EOVERFLOW);
    payload_mode=0; fail_next_copy=1;
    RUN(SUKISU_KPM_VERSION,out,256); assert(res==-EFAULT);
    assert(sukisu_handle_kpm(SUKISU_KPM_NUM,0,0,0)==-EFAULT);
    /* Execute actual repaired dynamic lookup with differing outer/member indices. */
    size_t offset=0,size=0;
    assert(!sukisu_super_access("alpha","z",&offset,&size) && offset==47 && size==8);
    assert(!sukisu_super_access("beta","w",&offset,&size) && offset==137 && size==6);
    assert(!sukisu_super_access("gamma","x",&offset,&size) && offset==257 && size==9);
    assert(sukisu_super_access("gamma","missing",&offset,&size)==-2);
    assert(sukisu_super_access("missing","x",&offset,&size)==-1);
    assert(!sukisu_super_access("alpha","x",NULL,NULL));
    puts("SUKISU_KPM_HOST_ASAN_UBSAN=PASS");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kernel', type=pathlib.Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('repair_kpm', HERE / 'repair-sukisu-kpm.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='sukisu-kpm-test-') as temp:
        temp = pathlib.Path(temp)
        source = temp / 'kernel'
        shutil.copytree(args.kernel / 'kpm', source / 'kpm')
        module.repair(source)
        text = (source / 'kpm/kpm.c').read_text()
        handler = text[text.index('static int sukisu_kpm_copy_string('):text.index('EXPORT_SYMBOL(sukisu_handle_kpm);')]
        do_kpm = text[text.index('int do_kpm(void __user *arg)\n'):]
        text = (source / 'kpm/super_access.c').read_text()
        lookup = text[text.index('int sukisu_super_access('):text.index('EXPORT_SYMBOL(sukisu_super_access);')]
        cfile = temp / 'test.c'
        cfile.write_text(PREFIX + handler + do_kpm + lookup + TESTS)
        binary = temp / 'test'
        subprocess.run([args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(cfile), '-o', str(binary)], check=True)
        # LeakSanitizer cannot inspect /proc threads in Work Mode; these tests
        # allocate no heap objects. Keep ASan's memory bounds and UBSan enabled.
        env = dict(os.environ)
        env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        subprocess.run([str(binary)], check=True, env=env)


if __name__ == '__main__':
    main()
