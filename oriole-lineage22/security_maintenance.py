#!/usr/bin/env python3
"""Pinned CVE-2026-31431 source backport; not a security patch-level claim."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

BASE = '536518ba56c64865b05abce6618077d91d3ef07e'
UPSTREAM = 'a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5'
STABLE = '961cfa271a918ad4ae452420e7c303149002875b'
SOURCE_SHA256 = 'd7235fb0e2966e17fa9b2777e813e67081b051a7aa1f00c4c0894cbb20e0d832'
SOURCE_PATH = 'crypto/algif_aead.c'
START = '\tprocessed = used + ctx->aead_assoclen;\n'
END = '\t/* Initialize the crypto operation */\n'
REPLACEMENT = '''\t/* Hold the complete input in a request-owned, read-only source SGL. */
\tprocessed = used + ctx->aead_assoclen;
\tareq->tsgl_entries = af_alg_count_tsgl(sk, processed, 0);
\tif (!areq->tsgl_entries)
\t\tareq->tsgl_entries = 1;
\tareq->tsgl = sock_kmalloc(sk, array_size(sizeof(*areq->tsgl),
\t\t\t\t\t         areq->tsgl_entries), GFP_KERNEL);
\tif (!areq->tsgl) {
\t\terr = -ENOMEM;
\t\tgoto free;
\t}
\tsg_init_table(areq->tsgl, areq->tsgl_entries);
\taf_alg_pull_tsgl(sk, processed, areq->tsgl, 0);
\ttsgl_src = areq->tsgl;
\trsgl_src = areq->first_rsgl.sgl.sg;

\t/* Only AAD is copied; input/tag pages never become writable output. */
\terr = crypto_aead_copy_sgl(null_tfm, tsgl_src, rsgl_src,
\t\t\t\t   ctx->aead_assoclen);
\tif (err)
\t\tgoto free;

'''

class MaintenanceError(RuntimeError):
    pass

def once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise MaintenanceError('Reviewed source anchor missing or duplicated')
    return text.replace(old, new, 1)

def transform(data: bytes) -> bytes:
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise MaintenanceError('Source differs from reviewed pinned preimage; refuse automatic rebase')
    text = data.decode('utf-8')
    text = once(text, '\tunsigned int i, as = crypto_aead_authsize(tfm);',
                '\tunsigned int as = crypto_aead_authsize(tfm);')
    text = once(text, '\tstruct af_alg_tsgl *tsgl, *tmp;\n', '')
    if text.count(START) != 1 or text.count(END) != 1:
        raise MaintenanceError('Ambiguous AEAD operation body')
    start, end = text.index(START), text.index(END)
    if start >= end:
        raise MaintenanceError('Invalid AEAD operation order')
    text = text[:start] + REPLACEMENT + text[end:]
    text = once(text, 'aead_request_set_crypt(&areq->cra_u.aead_req, rsgl_src,',
                'aead_request_set_crypt(&areq->cra_u.aead_req, tsgl_src,')
    if 'sg_chain(' in text or 'processed - as' in text:
        raise MaintenanceError('Legacy tag/output chain remains')
    return text.encode('utf-8')

def maintain(root: Path, output: Path, apply: bool = False) -> dict:
    path = root / SOURCE_PATH
    if output.resolve() == path.resolve() or output.is_symlink():
        raise MaintenanceError('Unsafe report destination')
    output.unlink(missing_ok=True)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size < 128*1024:
        raise MaintenanceError('Unexpected source file kind or size')
    old = path.read_bytes()
    new = transform(old)
    report = {
        'cve': 'CVE-2026-31431', 'base': BASE, 'upstream': UPSTREAM,
        'stable_reference': STABLE, 'path': SOURCE_PATH,
        'preimage_sha256': hashlib.sha256(old).hexdigest(),
        'postimage_sha256': hashlib.sha256(new).hexdigest(),
        'action': 'APPLIED_SOURCE_ONLY' if apply else 'VERIFIED_DRY_RUN',
        'adaptation': 'Retain Android null-cipher AAD copy and original exported AF_ALG helper signatures; pass zero offsets.',
        'compiled': False, 'device_tested': False,
        'security_patch_level_claim': None,
        'coverage': 'One source fix only; full kernel/framework/vendor bulletin coverage remains unaudited.'
    }
    if apply:
        # Refuse in-place changes to hard-linked source snapshots.
        if path.stat().st_nlink != 1:
            raise MaintenanceError('Refuse hard-linked source mutation')
        path.write_bytes(new)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return report

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--apply', action='store_true')
    a=p.parse_args()
    try:
        print(json.dumps(maintain(a.root,a.output,a.apply),indent=2))
        return 0
    except (MaintenanceError,OSError,UnicodeError) as exc:
        print('MAINTENANCE FAILED: '+str(exc))
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
