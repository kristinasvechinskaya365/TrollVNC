#!/usr/bin/env python3
"""Pinned oriole/Lineage 22.2 kernel build. No device writes or rollback bypasses."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
BASE = '3c76c2d71bb32039037c6f5dc38b172fe4142bdb'
BLU = '536518ba56c64865b05abce6618077d91d3ef07e'
RECIPE = '6374b323b459b8be265fae28b897e1cb578daf67'
FEATURES = ('SUS_PATH','SUS_MOUNT','SUS_KSTAT','SPOOF_UNAME','ENABLE_LOG',
            'HIDE_KSU_SUSFS_SYMBOLS','SPOOF_CMDLINE_OR_BOOTCONFIG','OPEN_REDIRECT','SUS_MAP')
REQUIRED = ['KSU','KPM','KSU_SUSFS','BBG','IKCONFIG','MODVERSIONS','MODULE_SIG',
            'MODULE_SIG_PROTECT','CFI_CLANG','SHADOW_CALL_STACK','RANDOMIZE_BASE',
            'SECURITY_SELINUX'] + ['KSU_SUSFS_' + f for f in FEATURES]
SOURCES = {
    'recipe': ('https://github.com/kristinasvechinskaya365/TrollVNC.git', RECIPE),
    'blu_spark': ('https://github.com/engstk/gs.git', BLU),
    'sukisu': ('https://github.com/SukiSU-Ultra/SukiSU-Ultra.git',
               '70fa0e092a2c81060823f8ae526eac14fdda2930'),
    'susfs': ('https://github.com/ShirkNeko/susfs4ksu.git',
              '24743360ea08d98f6ad72b856851abed8de5854f'),
    'bbg': ('https://github.com/vc-teahouse/Baseband-guard.git',
            'a54e0dc6cf0aff4dd87fec49644a02d2eb612905'),
    'lineage_manifest': ('https://github.com/LineageOS/android.git',
                         '98c181d61f032a69c817835238cbb40fd049100e'),
}

class BuildError(RuntimeError):
    pass

def run(args: list[str], cwd: Path | None = None, capture: bool = False) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    p = subprocess.run(args, cwd=cwd, env=env, text=True,
                       stdout=subprocess.PIPE if capture else None, check=True)
    return p.stdout.strip() if capture else ''

def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    tmp.replace(path)

def fetch(url: str, sha: str, dest: Path) -> None:
    if dest.exists():
        raise BuildError(f'Refusing to reuse nonempty checkout: {dest}')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise BuildError('Source must be pinned to a full commit SHA')
    dest.mkdir(parents=True)
    run(['git','init','-q',str(dest)])
    run(['git','remote','add','origin',url],dest)
    run(['git','fetch','--depth=1','--no-tags','origin',sha],dest)
    run(['git','checkout','--detach','FETCH_HEAD'],dest)
    if run(['git','rev-parse','HEAD'],dest,True) != sha:
        raise BuildError('Fetched commit differs from lock')

def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise BuildError(f'{label}: expected exactly one anchor, got {text.count(old)}')
    return text.replace(old,new,1)

def sanitize(root: Path) -> dict:
    """Replace the existing root provider, never layer two providers together."""
    result = {}
    for name, pattern in (
        ('drivers/Makefile', r'^obj-\$\(CONFIG_KSU\)\s*\+=\s*kernelsu/\s*$'),
        ('drivers/Kconfig', r'^source\s+"drivers/kernelsu/Kconfig"\s*$'),
    ):
        p = root / name
        text = p.read_text()
        lines = text.splitlines(keepends=True)
        hits = [i for i, line in enumerate(lines) if re.fullmatch(pattern,line.rstrip('\n'))]
        if len(hits) != 1:
            raise BuildError(f'{name}: unexpected upstream root wiring: {len(hits)}')
        p.write_text(''.join(line for i,line in enumerate(lines) if i not in hits))
        result[name] = {'removed_provider_entries': len(hits)}
    provider = root/'drivers/kernelsu'
    if provider.is_symlink():
        provider.unlink()
    elif provider.is_dir():
        shutil.rmtree(provider)
    elif provider.exists():
        raise BuildError('Unexpected root provider file')
    p = root/'arch/arm64/configs/gki_defconfig'
    lines = p.read_text().splitlines()
    provider_re = re.compile(r'^(?:CONFIG_(?:KSU(?:_\w+)?|KPM)=|# CONFIG_(?:KSU(?:_\w+)?|KPM) is not set$)')
    removed = [line for line in lines if provider_re.match(line)]
    p.write_text('\n'.join(line for line in lines if not provider_re.match(line))+'\n')
    result['old_root_config_removed'] = removed
    return result

def transform(recipe: Path, variant: str) -> None:
    if variant not in ('baseline','blu-spark'):
        raise BuildError('Invalid variant')
    if variant == 'baseline':
        return
    manifest = recipe/'default.xml'
    tree=ET.parse(manifest); root=tree.getroot()
    common=[p for p in root.findall('project') if p.get('path') == 'aosp']
    if len(common)!=1 or common[0].get('revision') != BASE:
        raise BuildError('Unexpected common kernel in baseline manifest')
    root.insert(0,ET.Element('remote',name='pinned-blu',fetch='https://github.com/'))
    common[0].set('remote','pinned-blu');common[0].set('name','engstk/gs')
    common[0].set('revision',BLU)
    tree.write(manifest,encoding='UTF-8',xml_declaration=True)
    p=recipe/'build.sh'; text=p.read_text()
    if text.count(BASE)!=2:
        raise BuildError('Unexpected source pin or provenance anchors')
    text=text.replace(BASE,BLU)
    text=replace_once(text,'python3 "$RECIPE/apply-kleaf-stamp.py" . "$OUT"',
        'python3 "$RECIPE/apply-kleaf-stamp.py" . "$OUT"\n'
        'python3 "$ROOT/oriole-lineage22/build.py" sanitize aosp', 'provider replacement')
    # Kernel identity must describe the actual fork, never pretend to be stock.
    text=text.replace('platform=Android 15 QPR2 source target',
                      'platform=oriole LineageOS 22.2 experimental blu_spark port')
    p.write_text(text)
    p=recipe/'verify.py';text=p.read_text()
    text=replace_once(text,"release.startswith('6.1.99-android14-11-g3c76c2d71bb3')",
        f"release.startswith('6.1.99-') and '-g{BLU[:12]}' in release",
        'truthful kernel release verification')
    p.write_text(text)

def prepare(work: Path, variant: str) -> Path:
    donor=work/'recipe'
    fetch(*SOURCES['recipe'],donor)
    target=donor/'oriole-lineage22';target.mkdir()
    shutil.copy2(__file__,target/'build.py')
    transform(donor/'pixel6-a15-qpr2',variant)
    write_json(work/'source-lock.json',{'variant':variant,'sources':SOURCES,
        'kernelpatch_commit':'e565c93ff6d0b992d9dfcbd43533a49d744a5f23',
        'root_uapi':5,'root_manager_version':40959,'susfs_version':'2.3.0',
        'features':REQUIRED,'framework_security_patch_level':'NOT_VERIFIED',
        'a17_to_a15_device_compatibility':'NOT_TESTED'})
    return donor

def port_audit(work: Path) -> None:
    """Check core patch application before spending a full toolchain sync."""
    donor=prepare(work,'blu-spark')
    source=work/'common'
    fetch(*SOURCES['blu_spark'],source)
    write_json(work/'provider-removal.json',sanitize(source))
    patch=donor/'pixel6-a15-qpr2/susfs-raviole.patch'
    run(['patch','--dry-run','--batch','--forward','--fuzz=0','-p1',
         '-i',str(patch.resolve())],source)
    write_json(work/'port-audit.json',{'core_patch_dry_run':'PASS',
        'compiled':False,'device_tested':False,'source':BLU})

def check_features(config: str) -> list[str]:
    actual={}
    for line in config.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key,value=line.split('=',1)
            if key in actual:raise BuildError(f'Duplicate config: {key}')
            actual[key]=value
    missing=[name for name in REQUIRED if actual.get('CONFIG_'+name)!='y']
    if missing:raise BuildError('Missing compiled features: '+', '.join(missing))
    return REQUIRED

def verify_output(output: Path, variant: str) -> None:
    if not (output/'Image').is_file():raise BuildError('No final Image')
    image=(output/'Image').read_bytes()
    check_features((output/'config.post-kpm').read_text())
    if (output/'config').read_bytes() != (output/'config.post-kpm').read_bytes():
        raise BuildError('Post-KPM config mismatch')
    if gzip.decompress((output/'Image.gz').read_bytes()) != image:
        raise BuildError('Compressed output differs from final Image')
    info=(output/'kpm-image-info.txt').read_text().splitlines()
    if 'patched=true' not in info or 'version=0xd00' not in info:
        raise BuildError('KPM postpatch evidence missing')
    mapfile=output/'source-dist-before-kpm/System.map'
    names={x.split()[-1] for x in mapfile.read_text().splitlines() if x.split()}
    if not {'susfs_init','bbg_init','sukisu_kpm_load_module_path'}<=names:
        raise BuildError('Required compiled symbols missing')
    write_json(output/'candidate-status.json',{
        'device':'oriole','target':'LineageOS 22.2 / Android 15', 'variant':variant,
        'kernel_build':'PASS','required_features':REQUIRED,
        'sha256_Image':hashlib.sha256(image).hexdigest(),
        'rom_built':False,'rom_module_compatibility':'NOT_TESTED',
        'security_patch_coverage':'NOT_AUDITED',
        'starting_firmware_compatibility':'NOT_TESTED',
        'physical_boot':'NOT_TESTED','flash_ready':False,
        'note':'A kernel payload is not a flashable matched ROM. No bootloader or radio is bundled.'})

def audit_rom_manifest(names: list[str]) -> dict:
    low={'abl','bl1','bl2','bl31','gsa','ldfw','modem','pbl','tzsw','bootloader','radio'}
    normalized=set()
    for name in names:
        p=Path(name)
        if p.is_absolute() or '..' in p.parts:raise BuildError('Unsafe image path')
        stem=p.name.removesuffix('.img')
        if stem.endswith(('_a','_b')):stem=stem[:-2]
        normalized.add(stem)
    blocked=sorted(n for n in normalized if n in low or n.startswith(('bootloader-','radio-')))
    if blocked:raise BuildError('Firmware-preserving bundle contains low-level writes: '+','.join(blocked))
    required={'boot','vendor_boot','dtbo','vbmeta','vbmeta_system','vbmeta_vendor'}
    if not required <= normalized:raise BuildError('Missing matched boot-stack components')
    return {'low_level_firmware_present':False,'flash_ready':False,
            'payload_manifest_inspection_still_required':True}

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('prepare');p.add_argument('work',type=Path)
    p.add_argument('--variant',choices=('baseline','blu-spark'),default='blu-spark')
    p=sub.add_parser('port-audit');p.add_argument('work',type=Path)
    p=sub.add_parser('sanitize');p.add_argument('root',type=Path)
    p=sub.add_parser('verify-output');p.add_argument('output',type=Path)
    p.add_argument('--variant',choices=('baseline','blu-spark'),default='blu-spark')
    a=parser.parse_args()
    try:
        if a.cmd=='prepare': print(prepare(a.work.resolve(),a.variant))
        elif a.cmd=='port-audit':port_audit(a.work.resolve())
        elif a.cmd=='sanitize':print(json.dumps(sanitize(a.root),indent=2))
        elif a.cmd=='verify-output':verify_output(a.output,a.variant)
        return 0
    except (BuildError,subprocess.CalledProcessError,OSError,ValueError) as e:
        print(f'BUILD FAILED: {e}',file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
