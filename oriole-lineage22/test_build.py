import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def put(self,path,text):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
    def provider(self):
        self.put('drivers/Makefile','obj-y += base/\nobj-$(CONFIG_KSU) += kernelsu/\n')
        self.put('drivers/Kconfig','menu "Drivers"\nsource "drivers/kernelsu/Kconfig"\nendmenu\n')
        self.put('arch/arm64/configs/gki_defconfig','CONFIG_KSU=y\nCONFIG_KPM=y\nCONFIG_KSU_DEBUG=y\nCONFIG_SECURITY_SELINUX=y\n')
    def test_feature_set(self):
        self.assertEqual(len(b.FEATURES),9)
        self.assertEqual(len(b.REQUIRED),len(set(b.REQUIRED)))
    def test_feature_success(self):
        self.assertEqual(b.check_features('\n'.join('CONFIG_'+x+'=y' for x in b.REQUIRED)),b.REQUIRED)
    def test_each_missing_feature_rejected(self):
        for feature in b.REQUIRED:
            with self.subTest(feature=feature),self.assertRaises(b.BuildError):
                b.check_features('\n'.join('CONFIG_'+x+'=y' for x in b.REQUIRED if x!=feature))
    def test_module_instead_of_builtin_rejected(self):
        with self.assertRaises(b.BuildError):
            b.check_features('\n'.join('CONFIG_'+x+('=m' if x=='KPM' else '=y') for x in b.REQUIRED))
    def test_duplicate_feature_rejected(self):
        with self.assertRaises(b.BuildError):b.check_features('CONFIG_KSU=y\nCONFIG_KSU=n\n')
    def test_provider_replacement(self):
        self.provider();self.put('drivers/kernelsu/test.c','old provider')
        result=b.sanitize(self.root)
        self.assertFalse((self.root/'drivers/kernelsu').exists())
        self.assertNotIn('CONFIG_KSU',(self.root/'drivers/Makefile').read_text())
        self.assertEqual((self.root/'arch/arm64/configs/gki_defconfig').read_text(),'CONFIG_SECURITY_SELINUX=y\n')
        self.assertEqual(len(result['old_root_config_removed']),3)
    def test_symlink_does_not_delete_target(self):
        self.provider();outside=self.root/'other-provider';outside.mkdir()
        (outside/'important').write_text('preserve')
        (self.root/'drivers/kernelsu').symlink_to(outside,target_is_directory=True)
        b.sanitize(self.root)
        self.assertTrue((outside/'important').exists())
    def test_missing_provider_anchor_rejected(self):
        self.provider();(self.root/'drivers/Makefile').write_text('obj-y += base/\n')
        with self.assertRaises(b.BuildError):b.sanitize(self.root)
    def test_duplicate_provider_anchor_rejected(self):
        self.provider();p=self.root/'drivers/Makefile';p.write_text(p.read_text()*2)
        with self.assertRaises(b.BuildError):b.sanitize(self.root)
    def test_replace_anchor_rejected(self):
        for text in ('none','aa'):
            with self.subTest(text=text),self.assertRaises(b.BuildError):b.replace_once(text,'a','b','test')
    def recipe(self):
        self.put('default.xml',f'<manifest><remote name="aosp" fetch="https://android.googlesource.com/"/><project name="kernel/common" path="aosp" revision="{b.BASE}"><linkfile src="x" dest="y"/></project></manifest>')
        self.put('build.sh',f'assert {b.BASE}\npython3 "$RECIPE/apply-kleaf-stamp.py" . "$OUT"\ncommon_commit={b.BASE}\nplatform=Android 15 QPR2 source target\n')
        self.put('verify.py',"assert release.startswith('6.1.99-android14-11-g3c76c2d71bb3'),release\n")
    def test_pinned_manifest_transform(self):
        self.recipe();b.transform(self.root,'blu-spark')
        root=ET.parse(self.root/'default.xml').getroot();p=root.find('project')
        self.assertEqual(p.get('revision'),b.BLU);self.assertEqual(p.get('remote'),'pinned-blu')
        self.assertIsNotNone(p.find('linkfile'))
        self.assertIn('sanitize aosp',(self.root/'build.sh').read_text())
        self.assertIn(b.BLU[:12],(self.root/'verify.py').read_text())
    def test_manifest_mismatch_rejected(self):
        self.recipe();p=self.root/'default.xml';p.write_text(p.read_text().replace(b.BASE,'0'*40))
        with self.assertRaises(b.BuildError):b.transform(self.root,'blu-spark')
    def test_unknown_variant_rejected(self):
        with self.assertRaises(b.BuildError):b.transform(self.root,'latest')
    def test_baseline_unchanged(self):
        self.recipe();before=(self.root/'build.sh').read_bytes();b.transform(self.root,'baseline')
        self.assertEqual(before,(self.root/'build.sh').read_bytes())
    def stack(self):return [x+'.img' for x in ('boot','vendor_boot','dtbo','vbmeta','vbmeta_system','vbmeta_vendor')]
    def test_low_level_firmware_rejected(self):
        for item in ('abl.img','bl1_b.img','radio-slider.img','bootloader-slider.img','modem_a.img','gsa.img'):
            with self.subTest(image=item),self.assertRaises(b.BuildError):b.audit_rom_manifest(self.stack()+[item])
    def test_unsafe_paths_rejected(self):
        for item in ('../boot.img','/boot.img'):
            with self.subTest(image=item),self.assertRaises(b.BuildError):b.audit_rom_manifest(self.stack()+[item])
    def test_missing_stack_rejected(self):
        with self.assertRaises(b.BuildError):b.audit_rom_manifest(['boot.img'])
    def test_image_list_is_not_a_flash_certification(self):
        result=b.audit_rom_manifest(self.stack())
        self.assertFalse(result['flash_ready']);self.assertTrue(result['payload_manifest_inspection_still_required'])
    def test_no_kernel_no_success(self):
        with self.assertRaises(b.BuildError):b.verify_output(self.root,'blu-spark')
    def test_all_source_refs_are_full_shas(self):
        for url,sha in b.SOURCES.values():
            self.assertRegex(sha,r'^[0-9a-f]{40}$');self.assertTrue(url.startswith('https://'))
    def test_atomic_report(self):
        p=self.root/'nested/proof.json';b.write_json(p,{'ok':True})
        self.assertEqual(json.loads(p.read_text()),{'ok':True});self.assertFalse(p.with_suffix('.json.tmp').exists())

if __name__=='__main__':unittest.main()
