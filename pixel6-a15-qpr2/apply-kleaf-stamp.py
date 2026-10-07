#!/usr/bin/env python3
"""Normalize the patched aosp release; preserve revision and other project stamps."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
source = root / 'build/kernel/kleaf/workspace_status_stamp.py'
original = source.read_bytes()
expected = 'd96e0a74056b133c4259ea401890922e61871f589da00da08e9c63d57461d61f'
assert hashlib.sha256(original).hexdigest() == expected, 'unpinned Kleaf stamp source'
text = original.decode()
anchor = '    popen = subprocess.Popen(script, shell=True, text=True,\n'
assert text.count(anchor) == 1
replacement = '''    # This recipe records patched source hashes separately. Keep the real
    # Google base SHA while omitting its incidental modified-worktree suffix.
    # Other projects retain their original dirty-state stamp.
    if project.resolve() == pathlib.Path("aosp").resolve():
        assert script.count("echo -n -dirty") == 1
        script = script.replace("echo -n -dirty", ": # recipe source hashes record modifications")
'''
source.write_text(text.replace(anchor, replacement + anchor, 1))

# Exercise the actual patched helper on clean and modified tracked files.
spec = importlib.util.spec_from_file_location('profile_kleaf_stamp', source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
old_cwd = Path.cwd()
old_build = os.environ.pop('BUILD_NUMBER', None)
results = {}
try:
    with tempfile.TemporaryDirectory(prefix='kleaf-stamp-proof-') as temp:
        os.chdir(temp)
        for name in ('aosp', 'vendor'):
            project = Path(name)
            subprocess.run(['git', 'init', '-q', name], check=True)
            tracked = project / 'tracked'
            tracked.write_text('original\n')
            subprocess.run(['git', '-C', name, 'add', 'tracked'], check=True)
            subprocess.run(['git', '-C', name, '-c', 'user.name=StampTest',
                            '-c', 'user.email=stamp@localhost', 'commit', '-qm', 'base'], check=True)
            sha = subprocess.check_output(['git', '-C', name, 'rev-parse', '--short=12', 'HEAD'], text=True).strip()
            expected_clean = '-g' + sha
            clean = module.get_localversion_from_git(project).collect()
            assert clean == expected_clean, (name, clean)
            tracked.write_text('modified\n')
            dirty = module.get_localversion_from_git(project).collect()
            assert dirty == expected_clean + ('' if name == 'aosp' else '-dirty'), (name, dirty)
            absolute = module.get_localversion_from_git(project.resolve()).collect()
            assert absolute == dirty
            os.environ['BUILD_NUMBER'] = '12345'
            numbered = module.get_localversion_from_git(project).collect()
            assert numbered == dirty + '-ab12345', (name, numbered)
            os.environ.pop('BUILD_NUMBER')
            results[name] = {'clean': clean, 'modified': dirty, 'absolute': absolute, 'numbered': numbered}
        assert module.get_localversion_from_git(Path('missing')) is None
finally:
    os.chdir(old_cwd)
    if old_build is not None:
        os.environ['BUILD_NUMBER'] = old_build

out.mkdir(parents=True, exist_ok=True)
proof = {'status': 'PASS', 'build_project_commit': '560e3751ab4d1d96e0db51e860f6437b41786c28',
         'path': str(source.relative_to(root)), 'original_sha256': expected,
         'patched_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'cases': results}
(out / 'profile-kleaf-stamp-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print('KLEAF_STAMP_SCOPE_AND_REVISION=PASS')
