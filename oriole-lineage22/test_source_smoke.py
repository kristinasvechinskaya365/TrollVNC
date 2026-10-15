import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('smoke_build',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class SourceSmoke(unittest.TestCase):
    def prepare(self, root, *, variation='good'):
        conf='\n'.join('CONFIG_'+n+'=y' for n in b.REQUIRED)+'\n'
        conf+='\n'.join('# CONFIG_'+n+' is not set' for n in b.DISABLED)
        conf+='\nCONFIG_LSM="selinux,baseband_guard"\n'
        if variation=='missing_flag':conf=conf.replace('CONFIG_KPM=y','CONFIG_KPM=n')
        body=('Linux version 6.1.99-android14-11-g'+b.BLU[:12]+' (unit)\0').encode()
        body+=b'IKCFG_ST'+gzip.compress(conf.encode(),mtime=0)+b'IKCFG_ED'
        (root/'Image').write_bytes(body)
        names=b.BRIDGES+('susfs_init','bbg_init')
        if variation=='missing_symbol':names=names[:-1]
        (root/'System.map').write_text('\n'.join('0000000000000000 T '+n for n in names)+'\n')
    def test_smoke_is_explicitly_not_flash_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.prepare(root);b.verify_source_smoke(root)
            result=json.loads((root/'source-smoke-status.json').read_text())
            self.assertEqual(result['compiled_features_count'],38)
            self.assertFalse(result['flash_ready']);self.assertFalse(result['kpm_final_patch_verified'])
            self.assertFalse(result['vendor_modules_verified'])
    def test_missing_flag_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.prepare(root,variation='missing_flag')
            with self.assertRaises(b.BuildError):b.verify_source_smoke(root)
    def test_missing_compiled_symbol_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.prepare(root,variation='missing_symbol')
            with self.assertRaises(b.BuildError):b.verify_source_smoke(root)
    def test_stale_success_removed_on_bad_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.prepare(root);b.verify_source_smoke(root)
            (root/'Image').write_bytes(b'bad')
            with self.assertRaises(b.BuildError):b.verify_source_smoke(root)
            self.assertFalse((root/'source-smoke-status.json').exists())
    def test_missing_system_map_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.prepare(root);(root/'System.map').unlink()
            with self.assertRaises(b.BuildError):b.verify_source_smoke(root)

if __name__=='__main__':unittest.main()
