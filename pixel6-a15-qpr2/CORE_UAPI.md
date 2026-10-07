# SukiSU core userspace API qualification

The pinned builtin source declares UAPI2 while already containing the scoped
su-session descriptor contract (API3) and services event contract (API5).
Its services event definition is missing, causing a real compiler failure.
Current official main ksud requires API5; a successful kernel compilation
without resolving this mismatch would not qualify that daemon's boot flow.

The compatibility reference is official SukiSU Ultra main
42d7fda3d787b7df90fc440a50bb9c8216a3fdef:
https://github.com/SukiSU-Ultra/SukiSU-Ultra/tree/42d7fda3d787b7df90fc440a50bb9c8216a3fdef

All 26 existing supercall wire structures and 54 existing constant/ioctl
expressions match that reference after comment/whitespace normalization,
except the declared API version. app_profile.h is byte-for-byte identical.
Existing scoped descriptors bypass ordinary authorization only for
GET_WRAPPER_FD and DISABLE_ESCAPE_TO_ROOT. The fs/exec adapter only creates a
scoped descriptor following allowed, successful su execution.

The guarded integration repair declares API5, EVENT_SERVICES=4 and BUNDLED
bit4. The built-in GET_INFO leaves LKM/BUNDLED/late-load flags clear, matching
that reference's built-in behavior. Services returns 1 for the first start,
0 for repeated starts, and resets following POST_FS_DATA. BOOT_COMPLETED=2
and MODULE_MOUNTED=3 remain unchanged.

Source-derived C tests exercise GET_INFO, service control, authorization and
post-exec handling together with the actual SELinux policy mutation function.
Their build output records the host qualification result. These tests are
not physical daemon, root manager or phone boot tests.

The reference main also has optional SukiSU ioctl commands104/105 for additional
spoof controls. Those are outside the documented core API3/4/5 changes and
are not backported or claimed here. The nine supported SUSFS2.3 configuration
features remain required independently.
