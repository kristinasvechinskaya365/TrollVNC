import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('module_kmi_audit',Path(__file__).with_name('module_kmi_audit.py'))
k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)
RELEASE='6.1.99-android14-11-g536518ba56c6'
SYMVERS='0x01234567 symbol_one vmlinux EXPORT_SYMBOL\n0x76543210 module_layout vmlinux EXPORT_SYMBOL_GPL\n'
VERSIONS='0x01234567 symbol_one\n0x76543210 module_layout\n'

def invoke(cmd):
    if cmd[0]=='modinfo':return RELEASE+' SMP preempt mod_unload modversions aarch64' if cmd[2]=='vermagic' else 'Google'
    if cmd[:2]==['modprobe','--dump-modversions']:return VERSIONS
    raise ValueError(cmd)

class KmiTests(unittest.TestCase):
    def fixture(self,tmp):
        root=Path(tmp);sym=root/'Module.symvers';sym.write_text(SYMVERS)
        mod=root/'ftm5.ko';mod.write_bytes(b'\x7fELF fake test module')
        return sym,mod
    def test_valid_exact_imports_not_flash_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            result=k.audit(sym,[mod],RELEASE,invoke)
            self.assertFalse(result['flash_ready'])
            self.assertFalse(result['complete_device_module_inventory_verified'])
            self.assertEqual(result['modules'][0]['crc_match_count'],2)
    def test_different_crc_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            sym.write_text(SYMVERS.replace('0x01234567','0x11111111'))
            with self.assertRaisesRegex(k.KmiError,'crc_mismatch'):k.audit(sym,[mod],RELEASE,invoke)
    def test_missing_symbol_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            sym.write_text('0x76543210 module_layout vmlinux EXPORT_SYMBOL_GPL\n')
            with self.assertRaisesRegex(k.KmiError,'missing=symbol_one'):k.audit(sym,[mod],RELEASE,invoke)
    def test_vermagic_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            with self.assertRaisesRegex(k.KmiError,'vermagic'):
                k.audit(sym,[mod],RELEASE,lambda cmd:('wrong-release' if cmd[0]=='modinfo' else VERSIONS))
    def test_duplicate_symvers_conflict_fails(self):
        with self.assertRaisesRegex(k.KmiError,'Conflicting exported'):
            k.read_symvers(SYMVERS+'0x11111111 symbol_one vmlinux EXPORT_SYMBOL\n')
    def test_symlink_module_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            link=Path(tmp)/'ref.ko';link.symlink_to(mod)
            with self.assertRaisesRegex(k.KmiError,'symlinked'):k.audit(sym,[link],RELEASE,invoke)
    def test_malformed_symbols_fail(self):
        for s in ['0x0123 x vmlinux EXPORT_SYMBOL','0x12345678 x','0x12345678 invalid&name vmlinux EXPORT_SYMBOL']:
            with self.subTest(s=s),self.assertRaises(k.KmiError):k.read_symvers(s)
    def test_duplicate_module_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            sym,mod=self.fixture(tmp)
            with self.assertRaisesRegex(k.KmiError,'Duplicate'):k.audit(sym,[mod,mod],RELEASE,invoke)

if __name__=='__main__':unittest.main()
