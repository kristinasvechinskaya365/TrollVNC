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
import zlib

HERE = Path(__file__).resolve().parent
BASE = '3c76c2d71bb32039037c6f5dc38b172fe4142bdb'
BLU = '536518ba56c64865b05abce6618077d91d3ef07e'
RECIPE = '6374b323b459b8be265fae28b897e1cb578daf67'
ARCH_SHA256 = '21951ac6769665243ce5962a8e55a54d01c9738eff1c3d3babbdd6dd8563cbb9'
FEATURES = ('SUS_PATH','SUS_MOUNT','SUS_KSTAT','SPOOF_UNAME','ENABLE_LOG',
            'HIDE_KSU_SUSFS_SYMBOLS','SPOOF_CMDLINE_OR_BOOTCONFIG','OPEN_REDIRECT','SUS_MAP')
REQUIRED = ['KSU','KPM','KALLSYMS','KALLSYMS_ALL','KSU_SUSFS','KSU_FEATURE_ADBROOT',
            'IKCONFIG','CFI_CLANG','SHADOW_CALL_STACK','RANDOMIZE_BASE','SECURITY_SELINUX',
            'SLAB_FREELIST_RANDOM','SLAB_FREELIST_HARDENED','MODVERSIONS','MODULE_SIG',
            'MODULE_SIG_PROTECT','KPROBES','BPF_SYSCALL','BPF_JIT','BPF_JIT_ALWAYS_ON',
            'LRU_GEN','LRU_GEN_ENABLED','DAMON','DAMON_VADDR','DAMON_SYSFS','BBG',
            'BPF_UNPRIV_DEFAULT_OFF','SECURITY_DMESG_RESTRICT','DEBUG_FS_DISALLOW_MOUNT'
            ] + ['KSU_SUSFS_' + f for f in FEATURES]
DISABLED = ('KSU_DEBUG','IKCONFIG_PROC','DEBUG_FS_ALLOW_ALL','DEBUG_FS_ALLOW_NONE',
            'BBG_BLOCK_BOOT','BBG_BLOCK_RECOVERY')
BRIDGES = ('sukisu_compact_find_symbol','sukisu_handle_kpm','sukisu_kpm_control',
           'sukisu_kpm_info','sukisu_kpm_list','sukisu_kpm_load_module_path',
           'sukisu_kpm_num','sukisu_kpm_unload_module','sukisu_kpm_version',
           'sukisu_super_access','sukisu_super_container_of','sukisu_super_find_struct')

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
    """Validate every edit before replacing the upstream root provider."""
    edits = {}
    result = {}
    for name, pattern in (
        ('drivers/Makefile', r'^obj-\$\(CONFIG_KSU\)\s*\+=\s*kernelsu/\s*$'),
        ('drivers/Kconfig', r'^source\s+"drivers/kernelsu/Kconfig"\s*$'),
    ):
        path = root / name
        if path.is_symlink():
            raise BuildError(f'Unexpected symlink: {name}')
        lines = path.read_text().splitlines(keepends=True)
        hits = [i for i, line in enumerate(lines) if re.fullmatch(pattern,line.rstrip('\n'))]
        if len(hits) != 1:
            raise BuildError(f'{name}: unexpected upstream root wiring: {len(hits)}')
        edits[path] = ''.join(line for i,line in enumerate(lines) if i not in hits)
        result[name] = {'removed_provider_entries': len(hits)}
    provider = root/'drivers/kernelsu'
    if provider.exists() and not provider.is_dir() and not provider.is_symlink():
        raise BuildError('Unexpected root provider file')
    config = root/'arch/arm64/configs/gki_defconfig'
    if config.is_symlink():
        raise BuildError('Unexpected config symlink')
    lines = config.read_text().splitlines()
    provider_re = re.compile(r'^(?:CONFIG_(?:KSU(?:_\w+)?|KPM)=|# CONFIG_(?:KSU(?:_\w+)?|KPM) is not set$)')
    result['old_root_config_removed'] = [line for line in lines if provider_re.match(line)]
    edits[config] = '\n'.join(line for line in lines if not provider_re.match(line))+'\n'
    for path, text in edits.items():
        path.write_text(text)
    if provider.is_symlink():
        provider.unlink()
    elif provider.is_dir():
        shutil.rmtree(provider)
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

def integration_fragment(text: str) -> str:
    start = "grep -qxF '#define SUSFS_VERSION \"v2.3.0\"'"
    end = 'BUILD_AOSP_KERNEL=1 '
    if text.count(start) != 1 or text.count(end) != 1:
        raise BuildError('Pinned integration fragment changed; review required')
    a, b = text.index(start), text.index(end)
    if a >= b:
        raise BuildError('Invalid source integration order')
    return text[a:b]


def verify_input(path: Path, expected_sha256: str) -> None:
    """Verify a small pinned source input without platform-specific checksum tools."""
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise BuildError('Expected input digest must be a full lowercase SHA-256')
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 8*1024*1024:
        raise BuildError('Pinned source input is missing, symlinked, empty or oversized')
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise BuildError('Pinned source input SHA-256 mismatch')


def portable_source_fragment(text: str) -> str:
    """Replace only the reviewed GNU checksum invocation; retain the donor hash."""
    fragment = integration_fragment(text)
    old = ("printf '%s  %s\\n' '" + ARCH_SHA256 +
           "' \"$RECIPE/compat/arch.h\" | sha256sum --check --status")
    new = ('python3 "$ROOT/oriole-lineage22/build.py" verify-input '
           '"$RECIPE/compat/arch.h" --sha256 ' + ARCH_SHA256)
    return replace_once(fragment, old, new, 'portable pinned arch.h verification')


def port_audit(work: Path) -> None:
    """Exercise all source integrations before the full 80-project build sync."""
    donor = prepare(work,'blu-spark')
    source = work/'aosp'
    fetch(*SOURCES['blu_spark'],source)
    write_json(work/'provider-removal.json',sanitize(source))
    for key, dest in [('sukisu','KernelSU'),('susfs','susfs4ksu'),('bbg','Baseband-guard')]:
        fetch(*SOURCES[key],work/dest)
    recipe = donor/'pixel6-a15-qpr2'
    fragment = portable_source_fragment((recipe/'build.sh').read_text())
    audit_out = work/'integration-evidence'
    audit_out.mkdir()
    script = work/'integration-only.sh'
    script.write_text('#!/usr/bin/env bash\nset -euo pipefail\n'
        'ROOT="$1"; RECIPE="$ROOT/pixel6-a15-qpr2"; OUT="$2"\n'
        'die() { echo "ERROR: $*" >&2; exit 1; }\n'+fragment)
    run(['bash',str(script),str(donor),str(audit_out)],work)
    write_json(work/'port-audit.json',{'source_integration':'PASS',
        'core_patch_dry_run':'PASS','profile_source_checks':'PASS',
        'integration_fragment_sha256':hashlib.sha256(fragment.encode()).hexdigest(),
        'compiled':False,'device_tested':False,'source':BLU})

def check_features(config: str) -> list[str]:
    actual={}
    for line in config.splitlines():
        enabled=re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)',line)
        disabled=re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set',line)
        if enabled or disabled:
            key,value=enabled.groups() if enabled else (disabled.group(1),'n')
            if key in actual:
                raise BuildError(f'Duplicate config: {key}')
            actual[key]=value
    missing=[name for name in REQUIRED if actual.get('CONFIG_'+name)!='y']
    if missing:
        raise BuildError('Missing compiled features: '+', '.join(missing))
    return REQUIRED

def embedded_config(image: bytes) -> bytes:
    """Read IKCONFIG from the actual binary, with a strict decompression limit."""
    if image.count(b'IKCFG_ST') != 1 or image.count(b'IKCFG_ED') != 1:
        raise BuildError('Image must contain exactly one embedded IKCONFIG stream')
    start = image.index(b'IKCFG_ST')+8
    end = image.index(b'IKCFG_ED')
    if end <= start:
        raise BuildError('Invalid IKCONFIG marker order')
    try:
        d = zlib.decompressobj(31)
        config = d.decompress(image[start:end],8*1024*1024+1)
        if len(config)>8*1024*1024 or not d.eof or d.unused_data or d.unconsumed_tail:
            raise BuildError('Invalid, oversized or concatenated IKCONFIG gzip')
        config.decode('ascii')
        return config
    except (zlib.error,UnicodeError) as e:
        raise BuildError(f'Invalid IKCONFIG: {e}') from e


def binary_identity(image: bytes, variant: str) -> str:
    sources = {'baseline':BASE,'blu-spark':BLU}
    if variant not in sources:
        raise BuildError('Unknown kernel variant')
    matches = set(re.findall(rb'Linux version (6\.1\.[0-9]+-[^ \x00]{1,160}) ',image))
    if len(matches)!=1:
        raise BuildError('Missing or ambiguous Linux release banner')
    release = next(iter(matches)).decode('ascii')
    expected = f'6.1.99-android14-11-g{sources[variant][:12]}'
    if release != expected:
        raise BuildError(f'Kernel identity mismatch: expected {expected}, got {release}')
    return release


def verify_output(output: Path, variant: str) -> None:
    report_path = output/'candidate-status.json'
    report_path.unlink(missing_ok=True)
    image_path = output/'Image'
    if not image_path.is_file() or not 0<image_path.stat().st_size<=128*1024*1024:
        raise BuildError('Final Image missing or exceeds bounded size')
    image=image_path.read_bytes()
    release=binary_identity(image,variant)
    config=embedded_config(image)
    check_features(config.decode('ascii'))
    for name in DISABLED:
        if f'# CONFIG_{name} is not set' not in config.decode('ascii').splitlines():
            raise BuildError(f'CONFIG_{name} must remain disabled')
    lsm=re.findall(rb'^CONFIG_LSM="([^"\n]+)"$',config,re.M)
    if len(lsm)!=1 or not {b'selinux',b'baseband_guard'}<=set(lsm[0].split(b',')):
        raise BuildError('SELinux/BBG LSM registration missing')
    for name in ('config','config.post-kpm'):
        if (output/name).read_bytes()!=config:
            raise BuildError(f'{name} differs from actual embedded configuration')
    try:
        with gzip.open(output/'Image.gz','rb') as stream:
            compressed_image=stream.read(len(image)+1)
        if compressed_image!=image:
            raise BuildError('Compressed output differs from final Image')
    except (OSError,EOFError,zlib.error) as e:
        raise BuildError(f'Invalid compressed kernel: {e}') from e
    info=(output/'kpm-image-info.txt').read_text().splitlines()
    if info!=['patched=true','version=0xd00'] or b'KPM_FAR_BRANCH_VENEER' not in image:
        raise BuildError('KPM postpatch evidence or binary marker missing')
    mapfile=output/'source-dist-before-kpm/System.map'
    names={x.split()[-1] for x in mapfile.read_text().splitlines() if x.split()}
    if not set(BRIDGES+('susfs_init','bbg_init'))<=names:
        raise BuildError('Required compiled bridge/initialization symbols missing')
    report={'device':'oriole','target':'LineageOS 22.2 / Android 15','variant':variant,
        'kernel_release':release,'kernel_build':'PASS','required_features':REQUIRED,
        'embedded_config_sha256':hashlib.sha256(config).hexdigest(),
        'sha256_Image':hashlib.sha256(image).hexdigest(),
        'rom_built':False,'rom_module_compatibility':'NOT_TESTED',
        'security_patch_coverage':'NOT_AUDITED','starting_firmware_compatibility':'NOT_TESTED',
        'physical_boot':'NOT_TESTED','flash_ready':False,
        'note':'Binary consistency check, not a cryptographic proof of source provenance or a matched ROM.'}
    write_json(report_path,report)

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
    p=sub.add_parser('verify-input');p.add_argument('path',type=Path)
    p.add_argument('--sha256',required=True)
    p=sub.add_parser('verify-output');p.add_argument('output',type=Path)
    p.add_argument('--variant',choices=('baseline','blu-spark'),default='blu-spark')
    a=parser.parse_args()
    try:
        if a.cmd=='prepare': print(prepare(a.work.resolve(),a.variant))
        elif a.cmd=='port-audit':port_audit(a.work.resolve())
        elif a.cmd=='sanitize':print(json.dumps(sanitize(a.root),indent=2))
        elif a.cmd=='verify-input':verify_input(a.path,a.sha256)
        elif a.cmd=='verify-output':verify_output(a.output,a.variant)
        return 0
    except (BuildError,subprocess.CalledProcessError,OSError,ValueError) as e:
        print(f'BUILD FAILED: {e}',file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
