import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('case_build',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class SourceCaseTests(unittest.TestCase):
    def fixture(self,root):
        folder=root/'net/netfilter';folder.mkdir(parents=True)
        for left,right in b.CASE_DISTINCT_NETFILTER:
            (folder/left).write_text('uppercase variant')
            (folder/right).write_text('lowercase variant')
        return folder
    def test_distinct_source_pairs_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            b.validate_case_sensitive_checkout(self.fixture(Path(tmp)).parents[1])
    def test_all_four_missing_collisions_rejected(self):
        for left,right in b.CASE_DISTINCT_NETFILTER:
            with self.subTest(left=left),tempfile.TemporaryDirectory() as tmp:
                folder=self.fixture(Path(tmp))
                (folder/left).unlink()
                with self.assertRaisesRegex(b.BuildError,'Case-folding'):
                    b.validate_case_sensitive_checkout(Path(tmp))
    def test_hardlink_alias_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=self.fixture(Path(tmp))
            a,c=b.CASE_DISTINCT_NETFILTER[0]
            (folder/c).unlink();(folder/c).hardlink_to(folder/a)
            with self.assertRaisesRegex(b.BuildError,'Case-folding'):
                b.validate_case_sensitive_checkout(Path(tmp))
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=self.fixture(Path(tmp))
            a,c=b.CASE_DISTINCT_NETFILTER[0]
            (folder/c).unlink();(folder/c).symlink_to(folder/a)
            with self.assertRaisesRegex(b.BuildError,'Case-folding'):
                b.validate_case_sensitive_checkout(Path(tmp))
    def test_no_netfilter_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(b.BuildError,'directory missing'):
                b.validate_case_sensitive_checkout(Path(tmp))

if __name__=='__main__':unittest.main()
