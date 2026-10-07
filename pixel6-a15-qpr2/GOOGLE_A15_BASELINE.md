# Google Pixel 6 Android 15 production baseline

The selected core source is Google's Pixel 6/raviole 6.1.99 Android 15
QPR2/May 2025 production source, not an emulator source.

Google's build table maps BP1A.250505.005 to android-15.0.0_r32 for Pixel 6:
https://source.android.com/docs/setup/reference/build-numbers

The exact platform manifest selects device/google/raviole-kernels/6.1:
https://android.googlesource.com/platform/manifest/+/refs/tags/android-15.0.0_r32/default.xml

Official prebuilt commit eddb1daf3ba7e38c2d9be1069f64fa234a1e5be8 identifies
Build-Id BP1A.250505.005:
https://android.googlesource.com/device/google/raviole-kernels/6.1/+/eddb1daf3ba7e38c2d9be1069f64fa234a1e5be8

Actual official 25Q1-13202328/softdog.ko was retrieved and SHA256 verified:
98f8e9e4407b7a7b8a5403bb32108ae90f6b97a9b4bb4d98a61a86ad31106aa9

Its embedded version string is:
6.1.99-android14-11-g3c76c2d71bb3-ab13202328 SMP preempt mod_unload modversions aarch64

The g3c76c2d71bb3 source prefix matches pinned core SHA
3c76c2d71bb32039037c6f5dc38b172fe4142bdb exactly. The android14 string is
the GKI generation used by this Android 15 platform, not an Android 14 ROM.

This establishes the production source lineage. It does not establish an
unknown Phantom Android 15 ROM's vendor/ramdisk/module compatibility or a
physical boot. The full 80-project source manifest remains independently
pinned using official stable project branches and the official topology.
