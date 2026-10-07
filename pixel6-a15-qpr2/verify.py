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
 'DAMON','DAMON_VADDR','DAMON_SYSFS']
missing=[x for x in required if 'CONFIG_'+x+'=y' not in config]
if '# CONFIG_KSU_DEBUG is not set' not in config:missing.append('KSU_DEBUG must be off')
assert not missing,missing
maps=list((out/'dist').glob('System.map'))
assert len(maps)==1,'System.map missing'
symbols=set(line.split()[-1] for line in maps[0].read_text().splitlines() if line.split())
needed=['sukisu_kpm_load_module_path','sukisu_kpm_unload_module','sukisu_kpm_control','susfs_init']
assert set(needed)<=symbols,sorted(set(needed)-symbols)
report={'compiled_config':'PASS','required':required,'compiled_symbols':needed,
 'proc_symbol_hiding':'compiled; runtime not tested',
 'CFI':'compiled on; KernelPatch permits selected CFI exceptions for its allocations',
 'physical_boot':'NOT_YET_TESTED','KPM_runtime':'NOT_YET_TESTED'}
(out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('COMPILED_CONFIG_AND_SYMBOLS=PASS')
