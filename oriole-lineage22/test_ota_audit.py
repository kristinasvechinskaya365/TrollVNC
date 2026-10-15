import base64
import hashlib
import importlib.util
import io
import struct
import tempfile
from pathlib import Path
import unittest
import warnings
import zipfile

spec=importlib.util.spec_from_file_location('ota_audit',Path(__file__).with_name('ota_audit.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

# Independent fixture encoder: no parser functions used to generate test input.
def vi(n):
    out=bytearray()
    while n>127:out.append((n&127)|128);n>>=7
    out.append(n);return bytes(out)
def field(tag,value):
    if isinstance(value,str):value=value.encode()
    return vi(tag<<3)+vi(value) if isinstance(value,int) else vi((tag<<3)|2)+vi(len(value))+value
DATA=b'x'*4096
DIGEST=hashlib.sha256(DATA).digest()
def part(name='boot',kind=0,extent_start=0,extent_count=1,duplicate=False,post=False,
         data_offset=0,data_length=4096,size=4096,old=False,extra=b''):
    info=field(1,size)+field(2,DIGEST)
    op=field(1,kind)+field(6,field(1,extent_start)+field(2,extent_count))
    if kind in (0,1,8):op+=field(2,data_offset)+field(3,data_length)+field(8,DIGEST)
    p=field(1,name)+field(7,info)+field(8,op)
    if duplicate:p+=field(8,op)
    if old:p+=field(6,info)
    if post:p+=field(2,1)+field(3,'bin/postinstall')
    return p+extra
def payload(parts=None,minor=0,partial=0,block=4096,extra=b'',metadata_sig=b'',trailer=b''):
    items=[part()] if parts is None else parts
    manifest=field(3,block)+field(12,minor)+field(16,partial)
    manifest+=b''.join(field(13,p) for p in items)+extra
    if trailer:manifest+=field(4,len(DATA))+field(5,len(trailer))
    header=struct.pack('>4sQQI',b'CrAU',2,len(manifest),len(metadata_sig))
    return header+manifest+metadata_sig+DATA+trailer,len(header+manifest)

class OtaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def inspect(self,body):return a.inspect_payload(io.BytesIO(body),len(body))
    def ota(self,body=None,metadata_extra='',pre_device='oriole',sdk='35',major='15',
            entries=None,mutate_props=None):
        if body is None:body,metadata_size=payload()
        else:metadata_size=24+struct.unpack('>Q',body[12:20])[0]
        metadata=(f'pre-device={pre_device}\nota-type=AB\npost-sdk-level={sdk}\n'
            f'post-build=google/oriole/oriole:{major}/TEST/1:user/release-keys\n'+metadata_extra)
        props={'FILE_SIZE':str(len(body)),'METADATA_SIZE':str(metadata_size),
            'FILE_HASH':base64.b64encode(hashlib.sha256(body).digest()).decode(),
            'METADATA_HASH':base64.b64encode(hashlib.sha256(body[:metadata_size]).digest()).decode()}
        if mutate_props:props.update(mutate_props)
        path=self.root/'test.zip'
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('META-INF/com/android/metadata',metadata)
            z.writestr('payload_properties.txt',''.join(k+'='+v+'\n' for k,v in props.items()))
            z.writestr('payload.bin',body)
            for name,data in (entries or []):z.writestr(name,data)
        return path,hashlib.sha256(path.read_bytes()).hexdigest()
    def test_full_payload(self):
        p,_=payload();r=self.inspect(p)
        self.assertEqual(r['partitions'][0]['name'],'boot')
        self.assertTrue(r['partitions'][0]['complete_extent_coverage'])
    def test_signed_metadata_hash_excludes_signature(self):
        body,size=payload(metadata_sig=b'signature',trailer=b'payloadsignature')
        path,digest=self.ota(body=body);r=a.inspect_ota(path,digest)
        self.assertEqual(r['metadata_size'],size)
        self.assertEqual(r['data_start'],size+9)
        self.assertTrue(r['metadata_signature_present'])
        self.assertEqual(r['signature_verification'],'NOT_PERFORMED')
    def test_header_magic(self):
        body,_=payload()
        with self.assertRaises(a.AuditError):self.inspect(b'XXXX'+body[4:])
    def test_major_version(self):
        body,_=payload();bad=body[:4]+struct.pack('>Q',3)+body[12:]
        with self.assertRaises(a.AuditError):self.inspect(bad)
    def test_manifest_limit(self):
        with self.assertRaises(a.AuditError):self.inspect(struct.pack('>4sQQI',b'CrAU',2,a.MAX_MANIFEST+1,0))
    def test_truncated_header(self):
        with self.assertRaises(a.AuditError):self.inspect(b'CrAU')
    def test_empty_partition_list(self):
        body,_=payload(parts=[])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_duplicate_partition(self):
        body,_=payload(parts=[part(),part()])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_partition_traversal_rejected(self):
        body,_=payload(parts=[part('../boot')])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_duplicate_singular_field(self):
        body,_=payload(extra=field(3,4096))
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_wrong_wire_type(self):
        with self.assertRaises(a.AuditError):a.single(a.fields(field(1,b'1')),1,0)
    def test_wire_group_rejected(self):
        with self.assertRaises(a.AuditError):a.fields(b'\x0b')
    def test_zero_field_number(self):
        with self.assertRaises(a.AuditError):a.fields(b'\x00\x00')
    def test_overflow_varint(self):
        with self.assertRaises(a.AuditError):a.varint(b'\xff'*10,0)
    def test_noncanonical_varint(self):
        with self.assertRaises(a.AuditError):a.varint(b'\x80\x00',0)
    def test_truncated_field(self):
        with self.assertRaises(a.AuditError):a.fields(b'\x0a\x08hi')
    def test_uint64_max_varint(self):
        self.assertEqual(a.varint(vi(2**64-1),0)[0],2**64-1)
    def test_invalid_block_size(self):
        body,_=payload(block=3000)
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_overlapping_extents(self):
        body,_=payload(parts=[part(duplicate=True)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_gap_in_full_image(self):
        body,_=payload(parts=[part(extent_start=1,size=8192)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_out_of_bounds_extent(self):
        body,_=payload(parts=[part(extent_start=1)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_out_of_bounds_data(self):
        body,_=payload(parts=[part(data_offset=1)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_delta_op_cannot_be_full(self):
        body,_=payload(parts=[part(kind=4)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_unknown_operation(self):
        body,_=payload(parts=[part(kind=99)])
        with self.assertRaises(a.AuditError):self.inspect(body)
    def test_delta_inventory_never_certified_full(self):
        body,_=payload(parts=[part(kind=4,old=True)],minor=2)
        path,digest=self.ota(body);r=a.inspect_ota(path,digest)
        self.assertFalse(r['source_independent_full_ota']);self.assertFalse(r['flash_ready'])
    def test_firmware_found_inside_payload(self):
        body,_=payload(parts=[part('boot'),part('abl')])
        path,digest=self.ota(body);r=a.inspect_ota(path,digest)
        self.assertEqual(r['firmware_partitions'],['abl'])
        self.assertFalse(r['firmware_absent_from_partition_inventory'])
    def test_unknown_partition_not_silently_allowed(self):
        body,_=payload(parts=[part('mystery')]);path,digest=self.ota(body)
        self.assertEqual(a.inspect_ota(path,digest)['unknown_partitions'],['mystery'])
    def test_complete_os_bundle_still_not_flash_ready(self):
        body,_=payload(parts=[part(n) for n in sorted(a.BOOT_PARTITIONS|{'system','vendor'})])
        path,digest=self.ota(body);r=a.inspect_ota(path,digest)
        self.assertTrue(r['required_boot_stack_present'])
        self.assertTrue(r['firmware_absent_from_partition_inventory'])
        self.assertFalse(r['firmware_preservation_proven']);self.assertFalse(r['flash_ready'])
    def test_postinstall_reported_not_executed(self):
        body,_=payload(parts=[part('system',post=True)])
        path,digest=self.ota(body);r=a.inspect_ota(path,digest)
        self.assertEqual(r['postinstall_partitions'],['system'])
        self.assertFalse(r['firmware_preservation_proven'])
    def test_loose_bootloader_found(self):
        path,digest=self.ota(entries=[('bootloader-slider.img',b'firmware')])
        self.assertEqual(a.inspect_ota(path,digest)['loose_firmware_images'],['bootloader-slider.img'])
    def test_archive_path_traversal(self):
        path,digest=self.ota(entries=[('../boot.img',b'data')])
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_duplicate_zip_entry(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore');path,digest=self.ota(entries=[('payload.bin',b'different')])
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_wrong_device(self):
        path,digest=self.ota(pre_device='raven')
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_wrong_sdk(self):
        path,digest=self.ota(sdk='36')
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_wrong_android_release(self):
        path,digest=self.ota(major='16')
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_duplicate_property(self):
        path,digest=self.ota(metadata_extra='pre-device=raven\n')
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_wrong_zip_hash(self):
        path,_=self.ota()
        with self.assertRaises(a.AuditError):a.inspect_ota(path,'0'*64)
    def test_wrong_payload_hash(self):
        path,digest=self.ota(mutate_props={'FILE_HASH':base64.b64encode(b'0'*32).decode()})
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_wrong_metadata_hash(self):
        path,digest=self.ota(mutate_props={'METADATA_HASH':base64.b64encode(b'0'*32).decode()})
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_malformed_hash(self):
        path,digest=self.ota(mutate_props={'FILE_HASH':'not-base64?'})
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_invalid_size_property(self):
        path,digest=self.ota(mutate_props={'FILE_SIZE':'0'})
        with self.assertRaises(a.AuditError):a.inspect_ota(path,digest)
    def test_partial_update_reported(self):
        body,_=payload(partial=1);path,digest=self.ota(body)
        self.assertFalse(a.inspect_ota(path,digest)['source_independent_full_ota'])

if __name__=='__main__':unittest.main()
