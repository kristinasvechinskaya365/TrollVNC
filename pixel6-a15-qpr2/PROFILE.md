# Restricted inspection profile

This profile extends the original qualified Pixel 6 / oriole Android 15 build.
It preserves SukiSU Ultra, all nine SUSFS 2.3 features, KPM, strict KMI checks,
symbol trimming, CFI, shadow call stack, SELinux, BPF and vendor-module support.

## Changes

| Area | Change |
| --- | --- |
| Config exposure | Disable IKCONFIG_PROC. Keep the exact embedded config in Image and verification artifacts. |
| Debugfs | Default to DEBUG_FS_DISALLOW_MOUNT, retaining the in-kernel API. A boot command-line override remains possible. |
| BTF | Keep BTF and BPF support; make the raw vmlinux BTF sysfs file mode 0400. Other privileged BTF APIs remain. |
| Addresses | Default kptr_restrict to 2. Standard privileged sysctl control remains. |
| Kernel logs | Enable SECURITY_DMESG_RESTRICT. Preserve security warnings, errors and root-access auditing. |
| BPF | Enable BPF_UNPRIV_DEFAULT_OFF. Privileged Android networking/BPF remains compiled. |
| SUSFS logs | Keep logging support, with its static key initially off. The manager can enable diagnostics. |
| SukiSU messages | Non-debug informational messages become debug messages; warnings/errors and separate sulog auditing remain. |
| Proc symbols | Namespace root-owned internal helpers and data as ksu_local_* and retain compiler/metadata filtering. Keep the normal kernel's same-named functions intact. Also cover the unprefixed SELinux wrapper names. Internal lookup and KMI exports remain available. |
| Release string | Retain the real Google base revision without the incidental worktree -dirty suffix. No Google build ID or phone fingerprint is invented. Source hashes and patches identify the modified build. |
| BBG | Integrate Baseband-guard a54e0dc6cf0aff4dd87fec49644a02d2eb612905 with standard LSM blobs; boot/recovery guard options remain off. |

BBG is partition-write protection, not hiding. Its source has been adapted to
avoid an unsynchronized/stale device-number authorization cache, initialize an
empty command-line diagnostic buffer, and consistently recognize allowlisted
partition names on both A/B slots. Build-time shell/network version discovery
is replaced by a pinned Makefile with private generated SELinux headers.
The default policy permits allowlisted boot/recovery/data partitions and denies
other block-device writes from processes BBG has marked untrusted. This does
not establish complete coverage of every root-grant or write path.

## Scope

The pinned SukiSU/SUSFS SELinux status, context, access-query and conditional
AVC-view features remain present. Their runtime controls still need matching
userspace configuration. Compilation does not establish that every hiding
control is enabled or effective on the phone.

Android 15's NetBpfLoad explicitly writes unprivileged_bpf_disabled back to 0
because networking consumers require it. The selected value 2 is an early boot
default that remains changeable; this profile does not pin it to 1 or block the
platform override. Likewise, Android init can change kptr/dmesg sysctls, and the
kernel command line can override debugfs defaults. Runtime values must be read
on the exact ROM. Source: Android platform/packages/modules/Connectivity,
refs/tags/android-15.0.0_r1/netbpfload/NetBpfLoad.cpp.

The generic SukiSU 69_hide_stuff patch was reviewed and excluded: it rewrites
Lineage mapping names and JIT mapping execution flags, which are not established
requirements for this unknown Phantom ROM. Optional upstream CPU-spoof commands
104/105 are not backported. This profile does not claim to change hardware
attestation, verified boot state, Play Integrity or biometric liveness.

BTF, KALLSYMS_ALL, Android debug metadata, Kprobes and required exports remain in
the image. Access restrictions and proc filtering are not universal removal of
symbols or strings. Root, kernel code and offline image inspection can still
inspect internals. KPM keeps its selective CFI exceptions.

## Validation

test-profile.py compiles actual C filter/partition/diagnostic functions with
ASan and UBSan and checks ordinary-symbol controls, compiler aliases, both A/B
slots, protected names and empty diagnostic buffers. It also tests the filter
against relevant names from the newly compiled System.map. verify.py requires
the final config, BBG LSM symbol and exact source-profile hashes.

The pinned Kleaf stamp generator is patched only for the aosp project; its real
base SHA remains. A test invokes the actual helper for clean/modified aosp and
vendor repositories, absolute paths and build-number suffixes. Other projects'
dirty-state stamps remain intact. Both original and patched generator hashes
are included in profile-kleaf-stamp-proof.json and verified after compilation.

Physical boot, privileged Android BPF consumers, vendor diagnostics, BBG runtime
enforcement, SELinux/SUSFS behavior and KPM load/unload still require device
qualification with the exact ROM. The final Image is not a matched boot.img.

Sources:
- https://github.com/vc-teahouse/Baseband-guard/tree/a54e0dc6cf0aff4dd87fec49644a02d2eb612905
- https://github.com/SukiSU-Ultra/SukiSU_patch/blob/547ae94bcaec53d030398f857950c64662043a5d/69_hide_stuff.patch
- Pinned Google/SukiSU/SUSFS revisions in build.sh and default.xml.
