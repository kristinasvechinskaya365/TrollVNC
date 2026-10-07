#!/usr/bin/env python3
"""Repair two pinned builtin integration omissions; upstream GPL-2.0 applies.

EVENT_SERVICES=4 comes from official SukiSU main42d7fda3d787b7df90fc440a50bb9c8216a3fdef,
uapi/supercall.h. Its userspace ksucalls.rs expects 1=start, 0=skip, which the
pinned builtin's existing service handler already implements. Wire comparison
against main found all 26 existing structures and 54 other constants/ioctls
unchanged, plus existing scoped su-session behavior. Restore its truthful UAPI5
declaration and the BUNDLED bit definition; built-in GET_INFO keeps that bit clear.
Optional main-only CPU/uname commands are not added or advertised.
"""
import hashlib
import pathlib
import sys

PINS = {
    'include/uapi/supercall.h': '0616e1f8b1daae295e7f848306560f1ca928b9271b3a9dbfe2f485566b39838f',
    'selinux/rules.c': 'bc1d2e172813f1f70d4a7d43c86781c407c4202dee8f5105c916c5c1ea58d892',
    'supercall/dispatch.c': 'a02963e0b3b0f1ef43fa56cc6586a652676692d4183a741829abdea1d06e62f1',
}


def once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f'ERROR: integration anchor count mismatch: {old!r}')
    return text.replace(old, new, 1)


def repair(kernel):
    kernel = pathlib.Path(kernel)
    for name, expected in PINS.items():
        if hashlib.sha256((kernel / name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f'ERROR: integration pinned source mismatch: {name}')
    header = kernel / 'include/uapi/supercall.h'
    text = once(header.read_text(),
                '// 2: allowlist v4 root profile flag\nDECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n',
                '// 2: allowlist v4 root profile flags\n'
                '// 3: scoped su-session driver fd\n'
                '// 4: add KSU_GET_INFO_FLAG_BUNDLED\n'
                '// 5: add EVENT_SERVICES with a start/skip result\n'
                'DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);\n')
    text = once(text, 'DECLARE(__u32, EVENT_MODULE_MOUNTED, 3);\n',
                'DECLARE(__u32, EVENT_MODULE_MOUNTED, 3);\n'
                '/* Existing builtin service handler: 1=start, 0=skip. */\n'
                'DECLARE(__u32, EVENT_SERVICES, 4);\n')
    text = once(text, 'DECLARE(__u32, KSU_GET_INFO_FLAG_PR_BUILD, (1U << 3));\n',
                'DECLARE(__u32, KSU_GET_INFO_FLAG_PR_BUILD, (1U << 3));\n'
                'DECLARE(__u32, KSU_GET_INFO_FLAG_BUNDLED, (1U << 4));\n')
    rules = kernel / 'selinux/rules.c'
    source = once(rules.read_text(),
                  'void apply_kernelsu_rules(void)\n{\n    struct selinux_policy *pol, *old_pol;\n',
                  'void apply_kernelsu_rules(void)\n{\n')
    source = once(source,
                  '    struct selinux_policy *pol, *old_pol = selinux_state.policy;\n',
                  '    struct selinux_policy *pol, *old_pol;\n')
    # old_pol is acquired by the existing protected RCU dereference after
    # locking policy_mutex, retaining policy duplication/swap and SELinux.
    header.write_text(text)
    rules.write_text(source)
    print('SUKISU_BUILTIN_INTEGRATION_SOURCE_REPAIR=PASS', flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: repair-sukisu-integration.py KERNELSU_KERNEL_DIRECTORY')
    repair(sys.argv[1])
