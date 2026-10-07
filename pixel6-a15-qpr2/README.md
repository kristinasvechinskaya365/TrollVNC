# Pixel 6 Android 15 QPR2 source kernel

This independent recipe builds Google Raviole (Pixel 6 / oriole) 6.1 sources,
SukiSU Ultra builtin, SUSFS v2.3.0 with every supported feature, and a repaired
SukiSU KernelPatch KPM payload. This is not an emulator kernel.

Google has no stable QPR2 manifest ref. default.xml uses the official beta
manifest topology, with all 80 project revisions resolved from their official
stable android-gs-raviole-6.1-android15-qpr2 branch and pinned to exact SHAs.
This reconstructed source target does not claim compatibility with an unknown
phone ROM fingerprint. The SUSFS patch adapts three context conflicts against
the pinned Google kernel, retaining the intended hooks (including smaps).

No prebuilt GKI substitution, CFI disabling, blanket symbol trimming disabling,
or ABI-check suppression is used. The final compiled config must retain KPM's
internal KALLSYMS_ALL and the SUSFS proc symbol hiding feature simultaneously.
System.map must contain the real SukiSU bridge and SUSFS entry points. KPM
bridge stubs require the mandatory post-build KernelPatch payload; configuration
alone is insufficient. The far branch relocation self-test is a build test,
not proof of runtime module loading on the phone.

Artifacts include Image, config, full dist, resolved manifest, verification,
postpatch inspection and provenance. No standalone KernelPatch key is published.
Image is not a flashable boot.img; the exact Android 15 ROM's boot/vendor/DTBO
compatibility and a physical boot + manager + KPM smoke test remain necessary.
This kernel does not establish camera injection, depth or biometric liveness.

Upstream source licenses apply: SukiSU Ultra GPL-3.0, Google Linux kernel GPL-2.0,
SUSFS GPL-2.0 and KernelPatch GPL-2.0. Sources are fetched at recorded revisions;
retain source manifests, integration patch and build scripts with distributions.
