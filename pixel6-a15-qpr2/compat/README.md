# Restored SukiSU architecture header

`arch.h` is copied byte for byte from official SukiSU Ultra:

- Repository: https://github.com/SukiSU-Ultra/SukiSU-Ultra
- Commit: `42d7fda3d787b7df90fc440a50bb9c8216a3fdef`
- Original path: `kernel/include/arch.h`
- Primary source: https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/42d7fda3d787b7df90fc440a50bb9c8216a3fdef/kernel/include/arch.h
- SHA-256: `21951ac6769665243ce5962a8e55a54d01c9738eff1c3d3babbdd6dd8563cbb9`
- License: upstream SukiSU Ultra GPL-2.0; upstream copyright and license apply.

The pinned builtin commit `70fa0e092a2c81060823f8ae526eac14fdda2930`
unconditionally includes this header but omits it from its tree. Its
`infra/kernel_compat.h` needs the register-access macros for kernel syscall
wrappers. Restoring the official header fixes this missing dependency without
removing wrappers or changing their ARM64 register mapping. Its ARM64 mapping
also matches the pinned dev revision `7755cdb36f63945f286d7b1cab662b42b18f2789`.

The builder verifies the donor hash and requires the destination to be absent
before copying. A host C test exercised all ARM64 argument, syscall argument,
return, frame, stack and program-counter macros against an ARM64-shaped
`pt_regs` structure. This verifies the macro mapping; full kernel compilation
and physical boot remain separate checks.
