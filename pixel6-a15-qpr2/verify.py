import pathlib,sys,json,re
out=pathlib.Path(sys.argv[1]);src=pathlib.Path(sys.argv[2])
config=set((out/'config').read_text().splitlines())
required=['KSU','KPM','KALLSYMS','KALLSYMS_ALL','KSU_SUSFS','KSU_FEATURE_ADBROOT',
 'KSU_SUSFS_SUS_PATH','KSU_SUSFS_SUS_MOUNT','KSU_SUSFS_SUS_KSTAT',
 'KSU_SUSFS_SPOOF_UNAME','KSU_SUSFS_ENABLE_LOG','KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS',
 'KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG','KSU_SUSFS_OPEN_REDIRECT','KSU_SUSFS_SUS_MAP',
 'IKCONFIG','CFI_CLANG','SHADOW_CALL_STACK','RANDOMIZE_BASE','SECURITY_SELINUX',
 'SLAB_FREELIST_RANDOM','SLAB_FREELIST_HARDENED','MODVERSIONS','MODULE_SIG','MODULE_SIG_PROTECT',
 'KPROBES','BPF_SYSCALL','BPF_JIT','BPF_JIT_ALWAYS_ON','LRU_GEN','LRU_GEN_ENABLED',
 'DAMON','DAMON_VADDR','DAMON_SYSFS','BBG','BPF_UNPRIV_DEFAULT_OFF',
 'SECURITY_DMESG_RESTRICT','DEBUG_FS_DISALLOW_MOUNT']
missing=[x for x in required if 'CONFIG_'+x+'=y' not in config]
if '# CONFIG_KSU_DEBUG is not set' not in config:missing.append('KSU_DEBUG must be off')
for name in ['IKCONFIG_PROC','DEBUG_FS_ALLOW_ALL','DEBUG_FS_ALLOW_NONE',
             'BBG_BLOCK_BOOT','BBG_BLOCK_RECOVERY']:
 if '# CONFIG_'+name+' is not set' not in config:missing.append(name+' must be off')
lsm=[line for line in config if line.startswith('CONFIG_LSM=')]
assert len(lsm)==1 and 'baseband_guard' in lsm[0] and 'selinux' in lsm[0],lsm
assert not missing,missing
maps=list((out/'dist').glob('System.map'))
assert len(maps)==1,'System.map missing'
symbols=set(line.split()[-1] for line in maps[0].read_text().splitlines() if line.split())
bridge=set()
for f in (src/'drivers/kernelsu/kpm').glob('*.c'):
 bridge.update(re.findall(r'EXPORT_SYMBOL\((\w+)\)',f.read_text()))
assert len(bridge)==12,'unexpected KPM bridge export set'
needed=sorted(bridge)+['susfs_init']
assert set(needed)<=symbols,sorted(set(needed)-symbols)
assert 'bbg_init' in symbols,'BBG LSM is absent from the compiled map'
profile_report=json.loads((out/'profile-source-sha256.json').read_text())
import hashlib
assert profile_report and all(hashlib.sha256((src/p).read_bytes()).hexdigest()==digest
                              for p,digest in profile_report.items())
release_match=re.search(rb'Linux version ([^ \x00]+) ',(out/'dist/Image').read_bytes())
assert release_match,'kernel release banner missing'
release=release_match.group(1).decode('ascii')
assert release.startswith('6.1.99-android14-11-g3c76c2d71bb3'),release
assert '-dirty' not in release,release
header=(src/'drivers/kernelsu/include/uapi/supercall.h').read_text()
assert 'DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);' in header
assert 'DECLARE(__u32, EVENT_SERVICES, 4);' in header
assert 'DECLARE(__u32, KSU_GET_INFO_FLAG_BUNDLED, (1U << 4));' in header
report={'compiled_config':'PASS','source_core_uapi':5,'required':required,'compiled_symbols':needed,
 'proc_symbol_hiding':'expanded filter compiled; see actual-C compiled-map proof; runtime not tested',
 'profile':'restricted-inspection-v1',
 'kernel_release':release,
 'BBG':'compiled and LSM configured; boot/recovery blocking off; runtime not tested',
 'restricted_interfaces':['proc/config.gz disabled','debugfs no-mount default',
                         'raw vmlinux BTF root-readable only','kptr_restrict default 2',
                         'dmesg restricted by default','unprivileged BPF disabled by default'],
 'logging':'SUSFS default off with support retained; SukiSU info becomes debug; warnings/errors/root audit retained',
 'CFI':'compiled on; KernelPatch permits selected CFI exceptions for its allocations',
 'physical_boot':'NOT_YET_TESTED','KPM_runtime':'NOT_YET_TESTED'}
(out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('COMPILED_CONFIG_AND_SYMBOLS=PASS')
