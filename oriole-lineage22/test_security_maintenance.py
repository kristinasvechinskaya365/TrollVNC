import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('maintenance',Path(__file__).with_name('security_maintenance.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

# Synthetic input verifies fail-closed transformations. The real pinned source
# must separately pass its full SHA-256 gate on the source-audit host.
FIXTURE=('\tunsigned int i, as = crypto_aead_authsize(tfm);\n'
         '\tstruct af_alg_tsgl *tsgl, *tmp;\n'+
         '\t\tif (used < less) {\n'+m.START+
         '\tlegacy body sg_chain(input, output);\n'+m.END+
         '\taead_request_set_crypt(&areq->cra_u.aead_req, rsgl_src,\n'
         '\t\t\t       areq->first_rsgl.sgl.sg, used, ctx->iv);\n').encode()

class MaintenanceTests(unittest.TestCase):
    def apply_fixture(self,data=FIXTURE):
        with patch.object(m,'SOURCE_SHA256',hashlib.sha256(data).hexdigest()):
            return m.transform(data).decode()
    def test_only_associated_data_copied(self):
        new=self.apply_fixture()
        self.assertIn('ctx->aead_assoclen);',new)
        self.assertIn('aead_request_set_crypt(&areq->cra_u.aead_req, tsgl_src,',new)
        self.assertNotIn('sg_chain(',new)
        self.assertNotIn('processed - as',new)
        self.assertIn('if (used < less + (ctx->enc ? 0 : as))',new)
        self.assertNotIn('if (used < less) {',new)
    def test_exported_helpers_keep_arity(self):
        new=self.apply_fixture()
        self.assertIn('af_alg_count_tsgl(sk, processed, 0)',new)
        self.assertIn('af_alg_pull_tsgl(sk, processed, areq->tsgl, 0)',new)
    def test_bad_preimage_rejected(self):
        with self.assertRaises(m.MaintenanceError):m.transform(FIXTURE)
    def test_duplicate_anchor_rejected(self):
        for anchor in (m.START,m.END,'\tstruct af_alg_tsgl *tsgl, *tmp;\n','\t\tif (used < less) {\n'):
            with self.subTest(anchor=anchor),self.assertRaises(m.MaintenanceError):
                self.apply_fixture(FIXTURE+anchor.encode())
    def test_missing_anchor_rejected(self):
        with self.assertRaises(m.MaintenanceError):self.apply_fixture(FIXTURE.replace(m.END.encode(),b''))
    def test_dry_run_and_second_application(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/m.SOURCE_PATH;source.parent.mkdir();source.write_bytes(FIXTURE)
            with patch.object(m,'SOURCE_SHA256',hashlib.sha256(FIXTURE).hexdigest()):
                result=m.maintain(root,root/'dry.json')
                self.assertEqual(source.read_bytes(),FIXTURE)
                self.assertFalse(result['compiled']);self.assertIsNone(result['security_patch_level_claim'])
                m.maintain(root,root/'apply.json',True)
                with self.assertRaises(m.MaintenanceError):m.maintain(root,root/'again.json',True)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/'target';target.write_bytes(FIXTURE)
            source=root/m.SOURCE_PATH;source.parent.mkdir();source.symlink_to(target)
            with self.assertRaises(m.MaintenanceError):m.maintain(root,root/'report.json',True)
    def test_hardlink_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/m.SOURCE_PATH;source.parent.mkdir();source.write_bytes(FIXTURE)
            (root/'linked').hardlink_to(source)
            with patch.object(m,'SOURCE_SHA256',hashlib.sha256(FIXTURE).hexdigest()):
                with self.assertRaises(m.MaintenanceError):m.maintain(root,root/'report.json',True)
            self.assertEqual(source.read_bytes(),FIXTURE)

if __name__=='__main__':unittest.main()
