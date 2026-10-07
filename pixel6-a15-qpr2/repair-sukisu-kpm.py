#!/usr/bin/env python3
"""Bounded fixes for the pinned SukiSU builtin KPM bridge (GPL-2.0-or-later).

The original GPL notice and Liankong attribution remain in the repaired source.
Whole-file SHA guards prevent accidentally applying this to another revision.
"""
import hashlib
import pathlib
import sys

KPM_SHA = '71ba6be828f26cd22d5420b8f136bd5060cd6493327fe2264ffaae8debb0ab2d'
SUPER_SHA = '4b58162024dd3e5fc237bd8a350cd12c9ce422abcebcbce05e4fdaf1044a1f36'

HANDLER = r'''static int sukisu_kpm_copy_string(unsigned long ptr, char *out, size_t size)
{
    long copied;

    if (!ptr || !access_ok((const void __user *)ptr, size))
        return -EFAULT;
    copied = strncpy_from_user(out, (const char __user *)ptr, size);
    if (copied < 0)
        return (int)copied;
    if ((size_t)copied >= size)
        return -ENAMETOOLONG;
    return (int)copied;
}

noinline int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1,
                               unsigned long arg2, unsigned long result_code)
{
    int res = -EOPNOTSUPP;
    int copied;

    if (!result_code || !access_ok((void __user *)result_code, sizeof(res)))
        return -EFAULT;
    if (control_code < SUKISU_KPM_LOAD || control_code > SUKISU_KPM_VERSION) {
        res = -EINVAL;
        goto exit;
    }

    if (control_code == SUKISU_KPM_LOAD) {
        char path[256] = { 0 };
        char args[256] = { 0 };

        copied = sukisu_kpm_copy_string(arg1, path, sizeof(path));
        if (copied <= 0) {
            res = copied ? copied : -EINVAL;
            goto exit;
        }
        if (arg2) {
            copied = sukisu_kpm_copy_string(arg2, args, sizeof(args));
            if (copied < 0) {
                res = copied;
                goto exit;
            }
        }
        sukisu_kpm_load_module_path(path, args, NULL, &res);
    } else if (control_code == SUKISU_KPM_UNLOAD) {
        char name[256] = { 0 };

        copied = sukisu_kpm_copy_string(arg1, name, sizeof(name));
        if (copied <= 0) {
            res = copied ? copied : -EINVAL;
            goto exit;
        }
        sukisu_kpm_unload_module(name, NULL, &res);
    } else if (control_code == SUKISU_KPM_NUM) {
        sukisu_kpm_num(&res);
    } else if (control_code == SUKISU_KPM_INFO) {
        char name[256] = { 0 };
        char buf[256] = { 0 };
        int size = -EOPNOTSUPP;

        copied = sukisu_kpm_copy_string(arg1, name, sizeof(name));
        if (copied <= 0) {
            res = copied ? copied : -EINVAL;
            goto exit;
        }
        if (!arg2) {
            res = -EFAULT;
            goto exit;
        }
        sukisu_kpm_info(name, buf, sizeof(buf), &size);
        if (size < 0) {
            res = size;
            goto exit;
        }
        if ((size_t)size > sizeof(buf)) {
            res = -ENOBUFS;
            goto exit;
        }
        if (!access_ok((void __user *)arg2, size) ||
            copy_to_user((void __user *)arg2, buf, size)) {
            res = -EFAULT;
            goto exit;
        }
        res = 0;
    } else if (control_code == SUKISU_KPM_LIST) {
        char buf[1024] = { 0 };
        size_t bytes;
        size_t capacity;

        if (!arg2) {
            res = -EINVAL;
            goto exit;
        }
        /* arg2 is caller capacity; larger buffers remain ABI-compatible. */
        capacity = arg2 < sizeof(buf) ? (size_t)arg2 : sizeof(buf);
        if (!arg1 || !access_ok((void __user *)arg1, capacity)) {
            res = -EFAULT;
            goto exit;
        }
        sukisu_kpm_list(buf, (int)capacity, &res);
        if (res < 0)
            goto exit;
        if ((size_t)res > capacity) {
            res = -ENOBUFS;
            goto exit;
        }
        bytes = res ? (size_t)res : 1;
        if (copy_to_user((void __user *)arg1, buf, bytes))
            res = -EFAULT;
    } else if (control_code == SUKISU_KPM_CONTROL) {
        char name[KPM_NAME_LEN] = { 0 };
        char args[KPM_ARGS_LEN] = { 0 };
        int args_len;

        copied = sukisu_kpm_copy_string(arg1, name, sizeof(name));
        if (copied <= 0) {
            res = copied ? copied : -EINVAL;
            goto exit;
        }
        args_len = sukisu_kpm_copy_string(arg2, args, sizeof(args));
        if (args_len < 0) {
            res = args_len;
            goto exit;
        }
        sukisu_kpm_control(name, args, args_len, &res);
    } else if (control_code == SUKISU_KPM_VERSION) {
        char buf[256] = { 0 };
        size_t bytes;
        size_t len;

        if (!arg2) {
            res = -EINVAL;
            goto exit;
        }
        if (!arg1) {
            res = -EFAULT;
            goto exit;
        }
        sukisu_kpm_version(buf, sizeof(buf));
        len = strnlen(buf, sizeof(buf));
        if (!len) {
            res = -EOPNOTSUPP;
            goto exit;
        }
        if (len == sizeof(buf)) {
            res = -EOVERFLOW;
            goto exit;
        }
        bytes = len + 1;
        if (bytes > arg2) {
            bytes = (size_t)arg2;
            buf[bytes - 1] = '\0';
        }
        if (!access_ok((void __user *)arg1, bytes) ||
            copy_to_user((void __user *)arg1, buf, bytes)) {
            res = -EFAULT;
            goto exit;
        }
        res = 0;
    }

exit:
    if (copy_to_user((void __user *)result_code, &res, sizeof(res)))
        return -EFAULT;
    return 0;
}
'''

DO_KPM = r'''int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    /* control_code is a scalar command, not a userspace address. */
    if (cmd.control_code < SUKISU_KPM_LOAD ||
        cmd.control_code > SUKISU_KPM_VERSION)
        return -EINVAL;
    if (!cmd.result_code ||
        !access_ok((void __user *)cmd.result_code, sizeof(int)))
        return -EFAULT;
    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2,
                             cmd.result_code);
}
'''


def repair(kernel):
    kernel = pathlib.Path(kernel)
    kpm = kernel / 'kpm/kpm.c'
    super_access = kernel / 'kpm/super_access.c'
    for path, expected in ((kpm, KPM_SHA), (super_access, SUPER_SHA)):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f'ERROR: pinned source hash mismatch for {path}: {actual}')
    text = kpm.read_text()
    start = text.index('noinline int sukisu_handle_kpm(')
    end = text.index('EXPORT_SYMBOL(sukisu_handle_kpm);', start)
    text = text[:start] + HANDLER + text[end:]
    start = text.index('int do_kpm(void __user *arg)\n')
    text = text[:start] + DO_KPM
    source = super_access.read_text()
    for member in ('offset', 'size'):
        old = f'*out_{member} = info->members[i].{member};'
        new = f'*out_{member} = info->members[i1].{member};'
        if source.count(old) != 1:
            raise SystemExit(f'ERROR: super_access anchor mismatch: {old}')
        source = source.replace(old, new, 1)
    kpm.write_text(text)
    super_access.write_text(source)
    print('SUKISU_KPM_BRIDGE_SOURCE_REPAIR=PASS')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: repair-sukisu-kpm.py KERNELSU_KERNEL_DIRECTORY')
    repair(sys.argv[1])
