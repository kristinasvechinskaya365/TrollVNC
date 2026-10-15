import gzip
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('binary_builder',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class BinaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def config(self):
        return ('\n'.join('CONFIG_'+x+'=y' for x in b.REQUIRED)+'\n'+
            '\n'.join('# CONFIG_'+x+' is not set' for x in b.DISABLED)+
            '\nCONFIG_LSM="selinux,baseband_guard"\n').encode()
    def image(self,variant='baseline',config=None):
        sha={'baseline':b.BASE,'blu-spark':b.BLU}[variant]
        cfg=self.config() if config is None else config
        return (f'Linux version 6.1.99-android14-11-g{sha[:12]} (test)\0'.encode()+
                b'IKCFG_ST'+gzip.compress(cfg,mtime=0)+b'IKCFG_EDKPM_FAR_BRANCH_VENEER')
    def output(self):
        image=self.image();config=self.config()
        for name,data in [('Image',image),('Image.gz',gzip.compress(image)),
            ('config',config),('config.post-kpm',config),
            ('kpm-image-info.txt',b'patched=true\nversion=0xd00\n')]:
            (self.root/name).write_bytes(data)
        folder=self.root/'source-dist-before-kpm';folder.mkdir()
        (folder/'System.map').write_text('\n'.join('00000000 T '+x for x in b.BRIDGES+('susfs_init','bbg_init')))
    def test_embedded_config_roundtrip(self):
        self.assertEqual(b.embedded_config(self.image()),self.config())
    def test_missing_config_marker_rejected(self):
        with self.assertRaises(b.BuildError):b.embedded_config(b'IKCFG_ST')
    def test_duplicate_config_marker_rejected(self):
        with self.assertRaises(b.BuildError):b.embedded_config(self.image()+self.image())
    def test_reversed_markers_rejected(self):
        with self.assertRaises(b.BuildError):b.embedded_config(b'IKCFG_EDIKCFG_ST')
    def test_invalid_config_gzip_rejected(self):
        with self.assertRaises(b.BuildError):b.embedded_config(b'IKCFG_STbadIKCFG_ED')
    def test_concatenated_gzip_rejected(self):
        with self.assertRaises(b.BuildError):b.embedded_config(b'IKCFG_ST'+gzip.compress(b'a')+gzip.compress(b'b')+b'IKCFG_ED')
    def test_decompression_limit(self):
        with self.assertRaises(b.BuildError):b.embedded_config(self.image(config=b'a'*(8*1024*1024+1)))
    def test_baseline_identity(self):
        self.assertIn(b.BASE[:12],b.binary_identity(self.image(),'baseline'))
    def test_blu_identity(self):
        self.assertIn(b.BLU[:12],b.binary_identity(self.image('blu-spark'),'blu-spark'))
    def test_baseline_cannot_be_relabeled_blu(self):
        with self.assertRaises(b.BuildError):b.binary_identity(self.image(),'blu-spark')
    def test_repeated_identical_banners_accepted(self):
        self.assertEqual(b.binary_identity(self.image()*2,'baseline'),b.binary_identity(self.image(),'baseline'))
    def test_conflicting_banners_rejected(self):
        with self.assertRaises(b.BuildError):b.binary_identity(self.image()+self.image('blu-spark'),'baseline')
    def test_unknown_variant_rejected(self):
        with self.assertRaises(b.BuildError):b.binary_identity(self.image(),'latest')
    def test_full_verifier_and_not_flash_ready(self):
        self.output();b.verify_output(self.root,'baseline')
        report=json.loads((self.root/'candidate-status.json').read_text())
        self.assertFalse(report['flash_ready']);self.assertEqual(len(report['required_features']),38)
    def test_sidecar_cannot_override_binary_config(self):
        self.output();(self.root/'config').write_bytes(self.config()+b'CONFIG_FAKE=y\n')
        with self.assertRaises(b.BuildError):b.verify_output(self.root,'baseline')
    def test_stale_success_removed(self):
        self.output();b.verify_output(self.root,'baseline')
        with self.assertRaises(b.BuildError):b.verify_output(self.root,'blu-spark')
        self.assertFalse((self.root/'candidate-status.json').exists())
    def test_mismatched_compressed_image_rejected(self):
        self.output();(self.root/'Image.gz').write_bytes(gzip.compress(b'other'))
        with self.assertRaises(b.BuildError):b.verify_output(self.root,'baseline')
    def test_all_twelve_bridges_required(self):
        self.output();p=self.root/'source-dist-before-kpm/System.map'
        p.write_text(p.read_text().replace('sukisu_super_find_struct','missing'))
        with self.assertRaises(b.BuildError):b.verify_output(self.root,'baseline')
    def test_integration_fragment_exact_start(self):
        start='grep -qxF \'#define SUSFS_VERSION "v2.3.0"\''
        text='earlier\n'+start+' header\napply_profile\nBUILD_AOSP_KERNEL=1 ./build\nlater'
        self.assertEqual(b.integration_fragment(text),start+' header\napply_profile\n')
    def test_fragment_multiple_anchors_rejected(self):
        with self.assertRaises(b.BuildError):b.integration_fragment('grep -qxF x\nBUILD_AOSP_KERNEL=1 ./build')
    def test_disabled_comment_cannot_duplicate_enabled_option(self):
        with self.assertRaises(b.BuildError):
            b.check_features(self.config().decode()+'# CONFIG_KSU is not set\n')
    def test_invalid_second_anchor_leaves_first_file_unchanged(self):
        drivers=self.root/'drivers';drivers.mkdir()
        makefile=drivers/'Makefile';makefile.write_text('obj-$(CONFIG_KSU) += kernelsu/\n')
        (drivers/'Kconfig').write_text('missing root provider anchor\n')
        original=makefile.read_bytes()
        with self.assertRaises(b.BuildError):b.sanitize(self.root)
        self.assertEqual(makefile.read_bytes(),original)
    def test_actual_preserved_baseline(self):
        path=os.environ.get('ORIOLE_BASELINE_DIR')
        if not path:self.skipTest('Set ORIOLE_BASELINE_DIR for a real binary regression')
        root=Path(path);b.verify_output(root,'baseline')
        image=(root/'Image').read_bytes()
        self.assertEqual(b.hashlib.sha256(image).hexdigest(),'754f203caa426b47665643ad6cbff1bbe73d5ba4e64c0b1c931e936801ee4012')
        with self.assertRaises(b.BuildError):b.verify_output(root,'blu-spark')
        b.verify_output(root,'baseline')

if __name__=='__main__':unittest.main()
