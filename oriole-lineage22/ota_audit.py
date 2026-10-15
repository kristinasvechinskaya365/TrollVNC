#!/usr/bin/env python3
"""Read-only Pixel 6 A15 OTA partition audit; never executes installers.

Wire fields follow AOSP system/update_engine/update_metadata.proto.
This inspects real payload.bin metadata, not a filename-based compatibility claim.
Signatures, postinstall executable behavior and physical boot remain unverified.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import zipfile

MAX_MANIFEST = 64 * 1024 * 1024
MAX_PAYLOAD = 16 * 1024**3
MAX_TEXT = 1024 * 1024
MAX_FIELDS = 1_000_000
OS_PARTITIONS = frozenset(('boot','vendor_boot','dtbo','vbmeta','vbmeta_system',
    'vbmeta_vendor','system','system_ext','product','vendor','vendor_dlkm',
    'system_dlkm','odm','odm_dlkm'))
BOOT_PARTITIONS = frozenset(('boot','vendor_boot','dtbo','vbmeta','vbmeta_system','vbmeta_vendor'))
FIRMWARE = frozenset(('abl','bl1','bl2','bl31','gsa','ldfw','modem','pbl','tzsw','bootloader','radio'))
FULL_OPS = frozenset((0,1,6,7,8))
MISSING = object()

class AuditError(ValueError):
    pass


def varint(data: bytes | memoryview, offset: int) -> tuple[int,int]:
    start, value = offset, 0
    for shift in range(0,70,7):
        if offset >= len(data):
            raise AuditError('Truncated protobuf varint')
        byte = data[offset]; offset += 1
        if shift == 63 and byte > 1:
            raise AuditError('Protobuf integer overflow')
        value |= (byte & 127) << shift
        if not byte & 128:
            if offset-start > 1 and byte == 0:
                raise AuditError('Noncanonical protobuf integer')
            return value, offset
    raise AuditError('Overlong protobuf varint')


def fields(data: bytes | memoryview) -> dict[int,list[tuple[int,object]]]:
    data = memoryview(data)
    result: dict[int,list[tuple[int,object]]] = {}
    offset = count = 0
    while offset < len(data):
        count += 1
        if count > MAX_FIELDS:
            raise AuditError('Too many protobuf fields')
        key, offset = varint(data,offset); number, wire = key >> 3, key & 7
        if not 0 < number < 2**29:
            raise AuditError('Invalid protobuf field number')
        if wire == 0:
            value, offset = varint(data,offset)
        elif wire in (1,2,5):
            if wire == 2:
                size, offset = varint(data,offset)
            else:
                size = 8 if wire == 1 else 4
            if size > len(data)-offset:
                raise AuditError('Truncated protobuf field')
            value = data[offset:offset+size]; offset += size
        else:
            raise AuditError('Unsupported protobuf wire type')
        result.setdefault(number,[]).append((wire,value))
    return result


def single(f: dict, number: int, wire: int, default=MISSING):
    entries = f.get(number,[])
    if not entries:
        if default is MISSING:
            raise AuditError(f'Missing required field {number}')
        return default
    if len(entries)!=1 or entries[0][0]!=wire:
        raise AuditError(f'Duplicate or mistyped field {number}')
    return entries[0][1]


def repeated(f: dict, number: int, wire: int) -> list:
    entries=f.get(number,[])
    if any(w!=wire for w,_ in entries):
        raise AuditError(f'Mistyped repeated field {number}')
    return [v for _,v in entries]


def text(value) -> str:
    try:
        return bytes(value).decode('utf-8')
    except UnicodeError as e:
        raise AuditError('Invalid UTF-8 metadata') from e


def read_exact(stream, size: int) -> bytes:
    data=stream.read(size)
    if len(data)!=size:
        raise AuditError('Truncated payload metadata')
    return data


def inspect_payload(stream, payload_size: int) -> dict:
    if not 24 <= payload_size <= MAX_PAYLOAD:
        raise AuditError('Payload size outside supported bounds')
    header=read_exact(stream,24)
    magic,major,manifest_size,signature_size=struct.unpack('>4sQQI',header)
    if magic!=b'CrAU' or major!=2:
        raise AuditError('Only Android payload format v2 is supported')
    if not 0<manifest_size<=MAX_MANIFEST or signature_size>MAX_TEXT:
        raise AuditError('Manifest or metadata signature exceeds limit')
    data_start=24+manifest_size+signature_size
    if data_start>payload_size:
        raise AuditError('Manifest exceeds payload')
    manifest=read_exact(stream,manifest_size)
    f=fields(manifest)
    block=single(f,3,0,4096)
    if not 512<=block<=65536 or block & (block-1):
        raise AuditError('Invalid block size')
    minor=single(f,12,0,0)
    partial=single(f,16,0,0)
    if partial not in (0,1):raise AuditError('Invalid partial-update flag')
    has_sig_offset=4 in f;has_sig_size=5 in f
    if has_sig_offset!=has_sig_size:
        raise AuditError('Incomplete payload signature bounds')
    data_size=payload_size-data_start
    if has_sig_offset:
        sig_offset=single(f,4,0);sig_size=single(f,5,0)
        if sig_size<=0 or sig_offset+sig_size!=data_size:
            raise AuditError('Payload signature bounds do not match file')
        data_size=sig_offset
    items=repeated(f,13,2)
    if not 1<=len(items)<=128:
        raise AuditError('Empty or excessive partition list')
    partitions=[];seen=set();total_ops=0
    for item in items:
        p=fields(item);name=text(single(p,1,2))
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',name) or name in seen:
            raise AuditError('Unsafe or duplicate partition name')
        seen.add(name)
        info=fields(single(p,7,2));size=single(info,1,0)
        digest=bytes(single(info,2,2))
        if not 0<size<=32*1024**3 or len(digest)!=32:
            raise AuditError('Invalid target partition size or hash')
        operations=repeated(p,8,2)
        total_ops+=len(operations)
        if not operations or total_ops>MAX_FIELDS:
            raise AuditError('Empty or excessive operation list')
        types=set();ranges=[]
        for encoded in operations:
            op=fields(encoded);kind=single(op,1,0);types.add(kind)
            if kind not in range(14):
                raise AuditError('Unknown operation type')
            if minor==0 and (kind not in FULL_OPS or 4 in op or 5 in op or 9 in op):
                raise AuditError('Source-dependent operation in full payload')
            offset=single(op,2,0,0);length=single(op,3,0,0)
            if offset>data_size or length>data_size-offset:
                raise AuditError('Operation reads beyond payload data')
            if kind in (0,1,8):
                if length==0 or len(bytes(single(op,8,2)))!=32:
                    raise AuditError('Replacement data/hash missing')
            if kind in (6,7) and (length or offset or 8 in op):
                raise AuditError('Unexpected data for ZERO/DISCARD')
            extents=repeated(op,6,2)
            if not extents:raise AuditError('Missing destination extents')
            for encoded_extent in extents:
                ex=fields(encoded_extent);start=single(ex,1,0);count=single(ex,2,0)
                if count==0 or (start+count)*block>((size+block-1)//block)*block:
                    raise AuditError('Destination extent exceeds partition')
                ranges.append((start,start+count))
        ranges.sort();cursor=0;gaps=False
        for start,end in ranges:
            if start<cursor:raise AuditError('Overlapping destination extents')
            if start!=cursor:gaps=True
            cursor=end
        complete=not gaps and cursor*block>=size
        if minor==0 and not complete:
            raise AuditError('Full payload has incomplete target coverage')
        post=single(p,2,0,0)
        if post not in (0,1):raise AuditError('Invalid postinstall flag')
        partitions.append({'name':name,'size':size,'sha256':digest.hex(),
            'operation_count':len(operations),'operation_types':sorted(types),
            'old_partition_info_present':6 in p,'complete_extent_coverage':complete,
            'postinstall_path':text(single(p,3,2,b'postinst')) if post else None})
    return {'major_version':major,'minor_version':minor,'partial_update':bool(partial),
        'metadata_size':24+manifest_size,'data_start':data_start,'block_size':block,
        'manifest_sha256':hashlib.sha256(manifest).hexdigest(),
        'security_patch_level':text(single(f,18,2,b'')) or None,
        'max_timestamp':single(f,14,0,None),'partitions':partitions,
        'metadata_signature_present':bool(signature_size),
        'payload_signature_present':has_sig_offset,
        'signature_verification':'NOT_PERFORMED',
        'partition_hashes':'DECLARED_BY_MANIFEST_NOT_RECONSTRUCTED'}


def properties(data: bytes) -> dict[str,str]:
    values={}
    for line in text(data).splitlines():
        if not line or line.startswith('#'):continue
        if '=' not in line:raise AuditError('Malformed properties line')
        key,value=line.split('=',1)
        if key in values or not key:raise AuditError('Duplicate or empty property')
        values[key]=value
    return values


def sha256_file(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def inspect_ota(path: Path, expected_sha256: str) -> dict:
    if not re.fullmatch(r'[a-f0-9]{64}',expected_sha256):
        raise AuditError('A full expected SHA-256 is required')
    observed=sha256_file(path)
    if observed!=expected_sha256:raise AuditError('ROM ZIP SHA-256 mismatch')
    with zipfile.ZipFile(path) as archive:
        inventory={}
        for info in archive.infolist():
            name=info.filename;parts=PurePosixPath(name).parts
            if (name in inventory or name.startswith('/') or '\\' in name or
                    '..' in parts or str(PurePosixPath(name))!=name.rstrip('/') or
                    (info.external_attr>>16)&0o170000==0o120000 or info.flag_bits&1):
                raise AuditError('Duplicate, encrypted or unsafe ZIP entry')
            inventory[name]=info
        required=('payload.bin','payload_properties.txt','META-INF/com/android/metadata')
        if not set(required)<=inventory.keys():raise AuditError('Not a complete Android A/B OTA ZIP')
        for name in required[1:]:
            if inventory[name].file_size>MAX_TEXT:raise AuditError('Oversized properties file')
        meta=properties(archive.read(required[2]));props=properties(archive.read(required[1]))
        if meta.get('pre-device')!='oriole' or meta.get('ota-type')!='AB':
            raise AuditError('OTA is not exclusively for Pixel 6 oriole A/B')
        if meta.get('post-sdk-level')!='35' or not re.fullmatch(
                r'[^/]+/oriole/oriole:15/[^\s]+',meta.get('post-build','')):
            raise AuditError('OTA metadata does not identify Android 15/API 35 oriole')
        payload_size=inventory['payload.bin'].file_size
        with archive.open('payload.bin') as stream:
            result=inspect_payload(stream,payload_size)
        if props.get('FILE_SIZE')!=str(payload_size) or props.get('METADATA_SIZE')!=str(result['metadata_size']):
            raise AuditError('Payload property sizes mismatch')
        try:
            hashes={k:base64.b64decode(props[k],validate=True) for k in ('FILE_HASH','METADATA_HASH')}
        except (KeyError,ValueError) as e:raise AuditError('Payload hashes missing or malformed') from e
        if any(len(v)!=32 for v in hashes.values()):raise AuditError('Payload digest length mismatch')
        full=hashlib.sha256();metadata=hashlib.sha256();offset=0
        with archive.open('payload.bin') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                full.update(chunk)
                if offset<result['metadata_size']:
                    metadata.update(chunk[:result['metadata_size']-offset])
                offset+=len(chunk)
        if offset!=payload_size or full.digest()!=hashes['FILE_HASH'] or metadata.digest()!=hashes['METADATA_HASH']:
            raise AuditError('Actual payload or metadata hash mismatch')
        names={p['name'] for p in result['partitions']}
        normalized={n[:-2] if n.endswith(('_a','_b')) else n for n in names}
        low=sorted(normalized&FIRMWARE)
        unknown=sorted(normalized-OS_PARTITIONS-FIRMWARE)
        loose_firmware=sorted(n for n in inventory if n.lower().endswith('.img') and
            any(PurePosixPath(n).stem==x or PurePosixPath(n).stem.startswith(x+'-') or
                PurePosixPath(n).stem in (x+'_a',x+'_b') for x in FIRMWARE))
        postinstall=[p['name'] for p in result['partitions'] if p['postinstall_path'] is not None]
        opaque=sorted(n for n in inventory if n.lower().endswith(('.zip','.sh','.bat','.exe')))
        complete=(BOOT_PARTITIONS|{'system','vendor'})<=names
        preserved=not(low or unknown or loose_firmware)
        result.update({'zip_sha256':observed,'payload_sha256':full.hexdigest(),
            'metadata':meta,'firmware_partitions':low,'unknown_partitions':unknown,
            'loose_firmware_images':loose_firmware,'postinstall_partitions':postinstall,
            'other_installer_or_archive_entries':opaque,'required_boot_stack_present':complete,
            'firmware_absent_from_partition_inventory':preserved,
            'source_independent_full_ota':result['minor_version']==0 and not result['partial_update']
                and not any(p['old_partition_info_present'] for p in result['partitions']),
            'firmware_preservation_proven':False,'flash_ready':False,
            'remaining':['Authenticate ROM signer independently','Inspect postinstall and installer behavior',
                'Verify retained firmware compatibility','Match boot layout and kernel-module ABI',
                'Physical boot and hardware qualification']})
        return result


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('ota',type=Path);p.add_argument('--expected-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.ota.resolve()==a.output.resolve():p.error('Output cannot replace the input ROM')
    # Preserve the audit outcome even when it fails, never stale success.
    try:
        report=inspect_ota(a.ota,a.expected_sha256)
        report['audit_status']='INSPECTED';code=0
    except (AuditError,OSError,zipfile.BadZipFile,RuntimeError) as e:
        report={'audit_status':'FAILED','error':str(e),'flash_ready':False};code=1
    a.output.parent.mkdir(parents=True,exist_ok=True)
    temp=a.output.with_name(a.output.name+'.tmp')
    temp.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');temp.replace(a.output)
    print(json.dumps(report,indent=2));return code

if __name__=='__main__':sys.exit(main())
