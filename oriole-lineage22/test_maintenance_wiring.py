import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('maintained_builder',Path(__file__).with_name('build.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class MaintenanceWiringTests(unittest.TestCase):
    def test_recipe_requires_patch_after_provider_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'default.xml').write_text('<manifest><project path="aosp" revision="'+b.BASE+'"/></manifest>')
            (root/'build.sh').write_text(b.BASE+'\npython3 "$RECIPE/apply-kleaf-stamp.py" . "$OUT"\n'+b.BASE+'\nBUILD_AOSP_KERNEL=1 build\n')
            (root/'verify.py').write_text("release.startswith('6.1.99-android14-11-g3c76c2d71bb3')")
            b.transform(root,'blu-spark')
            text=(root/'build.sh').read_text()
            self.assertEqual(text.count(b.MAINTENANCE_COMMAND),1)
            self.assertLess(text.index('sanitize aosp'),text.index(b.MAINTENANCE_COMMAND))
            self.assertLess(text.index(b.MAINTENANCE_COMMAND),text.index('BUILD_AOSP_KERNEL'))
    def test_prepare_copies_exact_maintenance_source_and_records_partial_coverage(self):
        for variant in ('blu-spark','baseline'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                def fake_fetch(url,sha,dest): dest.mkdir(parents=True)
                with patch.object(b,'fetch',fake_fetch),patch.object(b,'transform'):
                    donor=b.prepare(root,variant)
                copied=donor/'oriole-lineage22/security_maintenance.py'
                self.assertEqual(copied.exists(),variant=='blu-spark')
                if copied.exists():self.assertEqual(copied.read_bytes(),(b.HERE/'security_maintenance.py').read_bytes())
                lock=json.loads((root/'source-lock.json').read_text())
                self.assertEqual(lock['required_source_maintenance'],['CVE-2026-31431'] if variant=='blu-spark' else [])
                self.assertIn('NOT A PATCH LEVEL CERTIFICATION',lock['security_coverage'])
    def test_source_audit_refuses_failed_maintenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            calls=[]
            def fake_fetch(url,sha,dest):calls.append(dest.name)
            with patch.object(b,'prepare',return_value=root/'recipe'),patch.object(b,'fetch',fake_fetch),patch.object(b,'sanitize',return_value={}),patch.object(b,'run',side_effect=b.BuildError('preimage mismatch')):
                with self.assertRaises(b.BuildError):b.port_audit(root)
            self.assertEqual(calls,['aosp'])
            self.assertFalse((root/'port-audit.json').exists())

if __name__=='__main__':unittest.main()
