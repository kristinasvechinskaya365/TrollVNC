"""Regression for the real M2 GNU-sha256sum incompatibility."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('portable_builder',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class PortableSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def fragment(self):
        line=("printf '%s  %s\\n' '"+b.ARCH_SHA256+"' \"$RECIPE/compat/arch.h\" | sha256sum --check --status")
        return ('grep -qxF \'#define SUSFS_VERSION "v2.3.0"\' header\n'+line+'\ncp source dest\nBUILD_AOSP_KERNEL=1 ./build\n')
    def test_exact_pin_preserved(self):
        text=b.portable_source_fragment(self.fragment())
        self.assertIn('verify-input "$RECIPE/compat/arch.h" --sha256 '+b.ARCH_SHA256,text)
        self.assertNotIn('sha256sum',text);self.assertIn('cp source dest',text)
    def test_changed_hash_rejected(self):
        with self.assertRaises(b.BuildError):b.portable_source_fragment(self.fragment().replace(b.ARCH_SHA256,'0'*64))
    def test_duplicate_checksum_rejected(self):
        text=self.fragment();line=text.splitlines()[1]
        with self.assertRaises(b.BuildError):b.portable_source_fragment(text.replace(line,line+'\n'+line))
    def test_verified_input_and_cli(self):
        path=self.root/'space name.h';path.write_bytes(b'pinned\n');digest=hashlib.sha256(path.read_bytes()).hexdigest()
        b.verify_input(path,digest)
        subprocess.run([sys.executable,str(Path(b.__file__)),'verify-input',str(path),'--sha256',digest],check=True)
    def test_bad_bytes_rejected(self):
        path=self.root/'arch.h';path.write_bytes(b'pinned\n')
        with self.assertRaises(b.BuildError):b.verify_input(path,'0'*64)
    def test_invalid_source_kind_or_size(self):
        path=self.root/'arch.h';path.write_bytes(b'pinned\n')
        link=self.root/'link';link.symlink_to(path)
        empty=self.root/'empty';empty.touch()
        huge=self.root/'huge';huge.write_bytes(b'x'*(8*1024*1024+1))
        for item in (self.root/'missing',link,empty,huge,self.root):
            with self.subTest(item=item),self.assertRaises(b.BuildError):b.verify_input(item,'0'*64)
    def test_invalid_digest(self):
        path=self.root/'arch.h';path.write_bytes(b'pinned\n')
        for digest in ('','0'*63,'0'*65,'G'*64,'A'*64):
            with self.subTest(digest=digest),self.assertRaises(b.BuildError):b.verify_input(path,digest)

if __name__=='__main__':unittest.main()
