import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec=importlib.util.spec_from_file_location('rom_inputs', Path(__file__).with_name('rom_inputs.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class OrioleRomInputsTests(unittest.TestCase):
    def make_fixture(self,root):
        def put(rel,value):
            p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
        put('device/google/oriole/lineage.dependencies',json.dumps([{'repository':'android_device_google_raviole','target_path':'device/google/raviole'}]))
        put('device/google/raviole/lineage.dependencies',json.dumps([
            {'repository':'android_device_google_gs101','target_path':'device/google/gs101'},
            {'repository':'device/google/raviole-kernels/6.1','target_path':'device/google/raviole-kernels/6.1','remote':'aosp-raviole'}]))
        put('device/google/gs101/lineage.dependencies',json.dumps([{'repository':'android_device_google_gs-common','target_path':'device/google/gs-common'}]))
        put('device/google/raviole/lineage_oriole.mk','PRODUCT_NAME := lineage_$(DEVICE_CODENAME)\nBuildFingerprint=google/oriole/oriole:15/BP1A.250505.005/example\n')
        put('device/google/raviole/modules.load.vendor_boot','extra/ftm5.ko\nextra/sec_touch.ko\n')
        put('device/google/raviole/init.insmod.oriole.cfg','modprobe|bcmdhd4389.ko\nmodprobe|ftm5.ko\nmodprobe|sec_touch.ko\nmodprobe|st33spi.ko\n')
        put('device/google/raviole/BoardConfigLineage.mk','BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD_RAW = yes\nKERNEL_MODULE_DIR = present\n')
        put('device/google/gs101/BoardConfig-common.mk','BOARD_PREBUILT_BOOTIMAGE := x\nTARGET_NO_KERNEL := true\nAB_OTA_PARTITIONS += pvmfw\n')
        (root/'.repo/manifests').mkdir(parents=True)
        for path in r.PROJECTS: (root/path).mkdir(exist_ok=True)
    def git_reader(self,path):
        rel=str(path)
        if rel.endswith('.repo/manifests'):return r.MANIFEST
        for key,(_,sha) in r.PROJECTS.items():
            if rel.endswith(key):return sha
        return 'a'*40
    def test_manifest_exact_pins_and_remote(self):
        root=ET.fromstring(r.generate_manifest('a'*40))
        p=root.findall('project')
        self.assertEqual(len(p),5)
        for item in p: self.assertRegex(item.get('revision'),r'[0-9a-f]{40}')
        self.assertEqual(p[-1].get('path'),'device/google/raviole-kernels/6.1')
        self.assertEqual(p[-1].get('remote'),'oriole-aosp')
    def test_no_unpinned_prebuilt(self):
        for value in ['lineage-22.2','', '../escape','0'*39]:
            with self.subTest(value=value),self.assertRaises(r.InputError):r.generate_manifest(value)
    def test_known_tree_is_not_flash_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_fixture(root)
            report=r.source_snapshot(root,verify_git=self.git_reader)
            self.assertEqual(report['device'],'oriole')
            self.assertEqual(report['android_api'],35)
            self.assertFalse(report['flash_ready'])
            self.assertFalse(report['vendor_blobs_present'])
            self.assertFalse(report['module_inventory']['modversion_crc_verified'])
            self.assertEqual(report['module_inventory']['required'],sorted(r.EXPECTED_MODULES))
    def test_module_missing_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_fixture(root)
            p=root/'device/google/raviole/init.insmod.oriole.cfg'
            p.write_text(p.read_text().replace('modprobe|st33spi.ko\n',''))
            with self.assertRaisesRegex(r.InputError,'st33spi'):r.source_snapshot(root,verify_git=self.git_reader)
    def test_changed_dependencies_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_fixture(root)
            p=root/'device/google/raviole/lineage.dependencies'
            rows=json.loads(p.read_text());rows[1]['remote']='github';p.write_text(json.dumps(rows))
            with self.assertRaisesRegex(r.InputError,'remote changed'):r.source_snapshot(root,verify_git=self.git_reader)
    def test_changed_source_commit_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_fixture(root)
            with self.assertRaisesRegex(r.InputError,'Pinned device source mismatch'):
                r.source_snapshot(root,verify_git=lambda p:r.MANIFEST if str(p).endswith('.repo/manifests') else '0'*40)
    def test_symlink_module_manifest_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_fixture(root)
            p=root/'device/google/raviole/modules.load.vendor_boot'
            external=root/'unsafe';external.write_text(p.read_text());p.unlink();p.symlink_to(external)
            with self.assertRaisesRegex(r.InputError,'Unsafe'):r.source_snapshot(root,verify_git=self.git_reader)

if __name__=='__main__':unittest.main()
