#!/usr/bin/env python3
"""Fail-closed LineageOS 22.2/oriole source and module inventory.

No proprietary blobs are copied; no device access or firmware operation occurs.
A passing source inventory is *not* a build, signing, or flash qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

MANIFEST = '98c181d61f032a69c817835238cbb40fd049100e'
# Android 15 BP1A.250505.005 stock raviole kernel-and-modules REFERENCE,
# not the requested new blu_spark Image, module set or maintained kernel.
REFERENCE_A15_PREBUILT = 'eddb1daf3ba7e38c2d9be1069f64fa234a1e5be8'
PROJECTS = {
    'device/google/oriole': ('LineageOS/android_device_google_oriole', 'bec55ea9da934d3f0574392b809ebc3ccf34d33b'),
    'device/google/raviole': ('LineageOS/android_device_google_raviole', '4328bca33a7f40ee1ff8369e33b5fd9d5b18abb2'),
    'device/google/gs101': ('LineageOS/android_device_google_gs101', '04140bb2f4cf908f47327d7fbb596876398f72bf'),
    'device/google/gs-common': ('LineageOS/android_device_google_gs-common', '24c5f5467ceb80acd1b28748a34ea48f018286ee'),
}
EXPECTED_MODULES = frozenset({'bcmdhd4389.ko', 'ftm5.ko', 'sec_touch.ko', 'st33spi.ko'})
LOW_LEVEL = frozenset({'abl', 'bl1', 'bl2', 'bl31', 'gsa', 'ldfw', 'modem', 'pbl', 'tzsw', 'radio', 'bootloader'})
SHA = re.compile(r'[0-9a-f]{40}\Z')

class InputError(RuntimeError):
    pass

def generate_manifest(kernel_commit: str) -> str:
    if not SHA.fullmatch(kernel_commit):
        raise InputError('A verified 40-digit kernel prebuilt commit must be supplied; never guess a revision')
    root=ET.Element('manifest')
    ET.SubElement(root,'remote',name='oriole-lineage',fetch='https://github.com')
    ET.SubElement(root,'remote',name='oriole-aosp',fetch='https://android.googlesource.com')
    for path,(repo,sha) in PROJECTS.items():
        ET.SubElement(root,'project',name=repo,path=path,revision=sha,remote='oriole-lineage')
    ET.SubElement(root,'project',name='device/google/raviole-kernels/6.1',
                  path='device/google/raviole-kernels/6.1',revision=kernel_commit,remote='oriole-aosp')
    ET.indent(root)
    return '<?xml version="1.0" encoding="utf-8"?>\n'+ET.tostring(root,encoding='unicode')+'\n'

def read_text(root: Path, rel: str, max_bytes: int=128*1024) -> str:
    path=root/rel
    if path.is_symlink() or not path.is_file() or path.stat().st_size>max_bytes:
        raise InputError(f'Unsafe or missing required source file: {rel}')
    return path.read_text(encoding='utf-8')

def revparse(path: Path) -> str:
    result=subprocess.run(['git','-C',str(path),'rev-parse','HEAD'],text=True,capture_output=True,timeout=12)
    if result.returncode or not SHA.fullmatch(result.stdout.strip()):
        raise InputError('No verified Git commit at '+str(path))
    return result.stdout.strip()

def dependency_graph(root: Path) -> dict:
    for path,expect in (
        ('device/google/oriole/lineage.dependencies', [('android_device_google_raviole','device/google/raviole')]),
        ('device/google/raviole/lineage.dependencies', [('android_device_google_gs101','device/google/gs101'),('device/google/raviole-kernels/6.1','device/google/raviole-kernels/6.1')]),
        ('device/google/gs101/lineage.dependencies', [('android_device_google_gs-common','device/google/gs-common')]),
    ):
        rows=json.loads(read_text(root,path))
        if not isinstance(rows,list) or not all(isinstance(x,dict) for x in rows):
            raise InputError('Invalid dependency list: '+path)
        found=[]
        for x in rows:
            found.append((x.get('repository'),x.get('target_path')))
        # The pinned raviole kernel prebuilt is represented by its actual AOSP remote alias.
        if path.startswith('device/google/raviole/'):
            if rows[1].get('remote')!='aosp-raviole':
                raise InputError('Raviole kernel-prebuilt remote changed; review before building')
        if found!=expect:
            raise InputError('Pinned Lineage dependency graph changed: '+path)
    return {'checked':3,'prebuilt_path':'device/google/raviole-kernels/6.1'}

def module_inventory(root: Path) -> dict:
    vendor=read_text(root,'device/google/raviole/modules.load.vendor_boot')
    init=read_text(root,'device/google/raviole/init.insmod.oriole.cfg')
    vendor_names={Path(line.strip()).name for line in vendor.splitlines() if line.strip() and not line.lstrip().startswith('#')}
    init_names={line.split('|',1)[1].strip() for line in init.splitlines() if line.startswith('modprobe|')}
    found=vendor_names|init_names
    if not EXPECTED_MODULES<=found:
        raise InputError('Missing mandatory Pixel vendor module references: '+', '.join(sorted(EXPECTED_MODULES-found)))
    if any(not re.fullmatch(r'[A-Za-z0-9_.+-]+\.ko',name) for name in found):
        raise InputError('Unexpected kernel module name')
    board=read_text(root,'device/google/raviole/BoardConfigLineage.mk')
    if 'BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD_RAW' not in board or 'KERNEL_MODULE_DIR' not in board:
        raise InputError('Vendor ramdisk module loader architecture changed')
    return {'vendor_boot_load':sorted(vendor_names),'init_load':sorted(init_names),
            'required':sorted(EXPECTED_MODULES),'module_bytes_verified':False,
            'modversion_crc_verified':False,'load_order_runtime_verified':False}

def source_snapshot(root: Path, *, verify_git=revparse) -> dict:
    root=root.resolve(strict=True)
    hashes={}
    manifest=root/'.repo/manifests'
    if verify_git(manifest)!=MANIFEST:
        raise InputError('Lineage manifest SHA mismatch')
    for rel,(name,sha) in PROJECTS.items():
        p=root/rel
        if p.is_symlink() or verify_git(p)!=sha:
            raise InputError('Pinned device source mismatch: '+rel)
        hashes[rel]={'repository':name,'commit':sha}
    dependency_graph(root)
    product=read_text(root,'device/google/raviole/lineage_oriole.mk')
    if 'PRODUCT_NAME := lineage_$(DEVICE_CODENAME)' not in product or 'BuildFingerprint=google/oriole/oriole:15/' not in product:
        raise InputError('Lineage oriole product/Android 15 identity differs from reviewed reference')
    board=read_text(root,'device/google/gs101/BoardConfig-common.mk')
    if 'BOARD_PREBUILT_BOOTIMAGE :=' not in board or 'TARGET_NO_KERNEL := true' not in board:
        raise InputError('Raviole prebuilt-boot integration architecture changed')
    if 'AB_OTA_PARTITIONS += ' not in board or 'pvmfw' not in board:
        raise InputError('Product partition configuration changed')
    modules=module_inventory(root)
    vendor=root/'vendor/google/oriole/oriole-vendor.mk'
    kernel_prebuilt=root/'device/google/raviole-kernels/6.1'
    return {'schema_version':1,'device':'oriole','android_api':35,'lineage_manifest_commit':MANIFEST,
        'device_projects':hashes,'module_inventory':modules,
        'vendor_blobs_present':vendor.is_file() and not vendor.is_symlink(),
        'kernel_prebuilt_checkout_present':kernel_prebuilt.is_dir() and not kernel_prebuilt.is_symlink(),
        'kernel_prebuilt_sha':verify_git(kernel_prebuilt) if kernel_prebuilt.is_dir() else None,
        'stock_2025_reference_prebuilt_commit':REFERENCE_A15_PREBUILT,
        'kernel_prebuilt_matched_to_custom_image':False,
        'actual_partition_payload_audited':False,
        'low_level_firmware_write_prohibited':sorted(LOW_LEVEL),
        'retained_firmware_compatibility_proven':False,
        'full_rom_built':False,'flash_ready':False}

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('manifest');a.add_argument('--kernel-commit',required=True)
    a=sub.add_parser('snapshot');a.add_argument('workspace',type=Path);a.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    try:
        if args.cmd=='manifest':print(generate_manifest(args.kernel_commit),end='')
        else:
            report=source_snapshot(args.workspace)
            args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
            print(json.dumps(report,indent=2,sort_keys=True))
        return 0
    except (InputError,OSError,ValueError,KeyError,json.JSONDecodeError) as e:
        print('ROM INPUTS FAILED: '+str(e))
        return 1

if __name__=='__main__':raise SystemExit(main())
