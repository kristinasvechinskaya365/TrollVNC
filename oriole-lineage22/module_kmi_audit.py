#!/usr/bin/env python3
"""Fail-closed, host-only symbol CRC/vermagic audit for matched oriole modules.

Checks imports against the exact integrated tree's Module.symvers, not against
an overlapping subset. No ADB/Fastboot or device operations. A static match
never establishes boot or VINTF compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SHA = re.compile(r'0x[0-9a-fA-F]{8}\Z')
SYM = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
MAX_MODULE_BYTES = 64*1024*1024

class KmiError(RuntimeError):
    pass

def read_symvers(text: str) -> dict[str,str]:
    found={}
    for line in text.splitlines():
        if not line.strip():continue
        cols=line.split()
        if len(cols)<4 or len(cols)>5 or not SHA.fullmatch(cols[0]) or not SYM.fullmatch(cols[1]):
            raise KmiError('Malformed Module.symvers entry')
        symbol=cols[1];crc=cols[0].lower()
        if symbol in found and found[symbol]!=crc:
            raise KmiError('Conflicting exported symbol CRC: '+symbol)
        found[symbol]=crc
    if not found:raise KmiError('Empty Module.symvers')
    return found

def read_modversions(text: str) -> dict[str,str]:
    found={}
    for line in text.splitlines():
        if not line.strip():continue
        cols=line.split()
        if len(cols)!=2 or not SHA.fullmatch(cols[0]) or not SYM.fullmatch(cols[1]):
            raise KmiError('Malformed module required-CRC entry')
        symbol=cols[1];crc=cols[0].lower()
        if symbol in found and found[symbol]!=crc:
            raise KmiError('Conflicting module required CRC: '+symbol)
        found[symbol]=crc
    if not found:raise KmiError('Module contains no import CRCs')
    return found

def command(argv: list[str]) -> str:
    process=subprocess.run(argv,capture_output=True,text=True,timeout=20)
    if process.returncode:
        raise KmiError('Required module inspection command failed: '+argv[0])
    return process.stdout.strip()

def check_module(path: Path, exports: dict[str,str], kernel_release: str, invoke=command) -> dict:
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<MAX_MODULE_BYTES:
        raise KmiError('Missing, symlinked, empty or oversized module: '+path.name)
    vermagic=invoke(['modinfo','-F','vermagic',str(path)])
    if not vermagic or vermagic.split()[0]!=kernel_release:
        raise KmiError('Kernel vermagic mismatch for '+path.name)
    required=read_modversions(invoke(['modprobe','--dump-modversions',str(path)]))
    absent=sorted(required.keys()-exports.keys())
    conflict=sorted(k for k,v in required.items() if k in exports and exports[k]!=v)
    if absent or conflict:
        raise KmiError('KMI import failure in '+path.name+': missing='+','.join(absent[:12])+' crc_mismatch='+','.join(conflict[:12]))
    return {'filename':path.name,'bytes':path.stat().st_size,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'vermagic':vermagic,'import_count':len(required),'crc_match_count':len(required),
            'signer':invoke(['modinfo','-F','signer',str(path)]),
            'runtime_loaded':False}

def audit(symvers: Path, modules: list[Path], expected_release: str, invoke=command) -> dict:
    if symvers.is_symlink() or not symvers.is_file() or symvers.stat().st_size>32*1024*1024:
        raise KmiError('Missing or unsafe symbol map')
    if not re.fullmatch(r'6\.1\.[0-9]+-[A-Za-z0-9._+-]{2,160}',expected_release):
        raise KmiError('Missing exact kernel release')
    if not modules:raise KmiError('No explicitly selected modules to audit')
    if len({str(x) for x in modules})!=len(modules):raise KmiError('Duplicate module input')
    exports=read_symvers(symvers.read_text())
    return {'schema_version':1,'target':'oriole','kernel_release':expected_release,
            'symbol_map_sha256':hashlib.sha256(symvers.read_bytes()).hexdigest(),
            'export_count':len(exports),'modules':[check_module(p,exports,expected_release,invoke) for p in modules],
            'complete_device_module_inventory_verified':False,
            'module_runtime_verified':False,'full_rom_built':False,'flash_ready':False}

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--symvers',type=Path,required=True)
    p.add_argument('--kernel-release',required=True)
    p.add_argument('--modules',nargs='+',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        report=audit(a.symvers,a.modules,a.kernel_release)
        if a.output.is_symlink() or a.output.resolve() in ([a.symvers.resolve()]+[x.resolve() for x in a.modules]):
            raise KmiError('Unsafe report destination')
        a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps({'result':'PASS_SELECTED_MODULES_ONLY','count':len(a.modules),'flash_ready':False}))
        return 0
    except (KmiError,OSError,UnicodeError,subprocess.TimeoutExpired) as e:
        print('KMI AUDIT FAILED: '+str(e))
        return 1

if __name__=='__main__':raise SystemExit(main())
