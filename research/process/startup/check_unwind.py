"""Bind original Windows scope/helper bytes to composed native slice observation."""
from pathlib import Path
import hashlib,json,struct,subprocess,sys
from inventory import mapped_bytes
here=Path(__file__).resolve().parent
sys.path.insert(0,str(here.parents[2]/'corpus'))
from launch import execute
def verify_observation(report, stdout, stderr, frozen):
    """An edited report cannot become the independent native expected result."""
    if report.get('exit') != frozen['expected_exit'] or type(report.get('exit')) is not int:
        raise ValueError('original exit differs from frozen expectation')
    if report.get('stdout_hex') != stdout.hex() or report.get('stderr_hex') != stderr.hex():
        raise ValueError('report differs from retained original output')
    if stderr.hex() != frozen['expected_stderr_hex']:
        raise ValueError('original stderr differs from frozen expectation')
    observed = json.loads(stdout)
    if observed != report.get('observation'):
        raise ValueError('report observation differs from original stdout')
    if report.get('expected') != frozen['expected_observation']:
        raise ValueError('report expected outcomes differ from independent freeze')
    for key, expected in frozen['expected_observation'].items():
        if type(observed.get(key)) is not int or observed[key] != expected:
            raise ValueError('original observation differs from independent freeze: '+key)
    return observed


def verify_evidence(root):
    from measure_unwind import cleanup_instructions, verified_code, RESTORE_INSTRUCTIONS
    from coff_binding import dispatcher_evidence
    frozen = json.loads((here/'unwind-frozen.json').read_text())
    retained = json.loads((root/'unwind-frozen.json').read_text())
    if retained != frozen:
        raise ValueError('retained freeze differs from repository freeze')
    r = json.loads((root/'report.json').read_text())
    if sha((root/'unwind_probe.c').read_bytes()) != frozen['source_sha256'] or r.get('source_sha256') != frozen['source_sha256']:
        raise ValueError('original source identity differs from freeze')
    command = r.get('command', [])
    if (len(command) != 8 or command[0] != 'cl' or command[1:5] != frozen['compiler_flags']
            or not command[5].replace('\\','/').endswith('/unwind_probe.c')
            or not command[6].startswith('/Fe') or not command[7].startswith('/Fo')
            or not r.get('vc_tools_version','').startswith('14.44.')
            or r.get('limits') != frozen['limits']):
        raise ValueError('reported configuration or scope differs from freeze')
    obs = verify_observation(r, (root/'stdout').read_bytes(), (root/'stderr').read_bytes(), frozen)
    pe = (root/'unwind.exe').read_bytes()
    if sha(pe) != r['pe_sha256']:
        raise ValueError('retained PE changed')
    launch = json.loads((root/'launch/launch.json').read_text())
    if (launch.get('executed_sha256') != sha(pe) or sha((root/'launch/program.bin').read_bytes()) != sha(pe)
            or launch.get('stage') != 'finished' or launch.get('timeout') is not False
            or 'failure' in launch or launch.get('exit') != frozen['expected_exit']
            or launch.get('expected') != frozen
            or launch.get('stdout_hex') != r['stdout_hex'] or launch.get('stderr_hex') != r['stderr_hex']
            or (root/'launch/stdout').read_bytes() != (root/'stdout').read_bytes()
            or (root/'launch/stderr').read_bytes() != (root/'stderr').read_bytes()):
        raise ValueError('original launch provenance does not establish the claimed observation')
    header = struct.unpack_from('<I',pe,60)[0]
    if pe[header:header+4] != b'PE\0\0' or struct.unpack_from('<H',pe,header+4)[0] != 0x14c or struct.unpack_from('<H',pe,header+24)[0] != 0x10b:
        raise ValueError('original is not x86 PE32')
    base = struct.unpack_from('<I',pe,header+52)[0]
    if r['image_base'] != base or r['table_rva'] != obs['table_rva']:
        raise ValueError('original image/table identity changed')
    if r['scope_table_size'] != 24 or len(r['cleanups']) != 3:
        raise ValueError('frozen table/code count changed')
    table = mapped_bytes(pe,base+r['table_rva'],24)
    if sha(table) != r['scope_table_sha256'] or table != (root/'scope-table.bin').read_bytes() or table.hex() != r['scope_table_hex']:
        raise ValueError('original scope binding')
    rows = []
    for expected, block, rva in zip(frozen['scope_rows'],r['cleanups'],obs['cleanup_rvas']):
        if block['name'] != expected['target'] or block['file'] != expected['target']+'.bin' or block['rva'] != rva:
            raise ValueError('cleanup symbol identity changed')
        parent, target = struct.unpack_from('<iI',table,expected['index']*8)
        if parent != expected['parent'] or target != base+rva:
            raise ValueError('original scope parent or target differs from freeze')
        rows.append(dict(index=expected['index'],parent=parent,target_rva=rva,owner=expected['owner']))
        code = verified_code(lambda offset,size:mapped_bytes(pe,base+rva+offset,size),
                             cleanup_instructions(expected['trace_digit'],expected['local_delta']))
        verify_block(root, block, code)
    if len(obs['cleanup_rvas']) != 3 or r['scope_rows'] != rows:
        raise ValueError('scope report differs from original table')
    block = r['restore']
    if block['name'] != 'Restore' or block['file'] != 'Restore.bin' or block['rva'] != obs['restore_rva']:
        raise ValueError('restore symbol identity changed')
    code = verified_code(lambda offset,size:mapped_bytes(pe,base+block['rva']+offset,size),RESTORE_INSTRUCTIONS)
    verify_block(root,block,code)
    if r['restore_target_rva'] != obs['restore_target_rva']:
        raise ValueError('restore target differs from original observation')
    dispatcher = dispatcher_evidence((root/'unwind.obj').read_bytes(),pe,r['table_rva'])
    if 'dispatcher' in r and r['dispatcher'] != dispatcher:
        raise ValueError('dispatcher report differs from original COFF/PE binding')
    dispatch_file = root/dispatcher['file']
    if dispatch_file.exists() and dispatch_file.read_bytes() != bytes.fromhex(dispatcher['code_hex']):
        raise ValueError('retained dispatcher bytes differ from original COFF/PE binding')
    # Earlier immutable Windows records predate this static derivation. Derive
    # it from the retained object and PE; do not alter those original reports.
    r['dispatcher'] = dispatcher
    return r, pe, base, table


def verify_block(root, block, code):
    if block['size'] != len(code) or block['code_hex'] != code.hex() or block['sha256'] != sha(code) or (root/block['file']).read_bytes() != code:
        raise ValueError('original instruction bytes differ from retained code report')


sha=lambda b:hashlib.sha256(b).hexdigest()


def main(root, compiler):
    r, pe, base, table = verify_evidence(root)
    (root/r['dispatcher']['file']).write_bytes(bytes.fromhex(r['dispatcher']['code_hex']))
    (root/'dispatch.bin').write_bytes(bytes.fromhex(r['dispatcher']['code_hex']))
    (root/'dispatch.bind').write_text(str(r['dispatcher']['rva'])+' '+str(r['dispatcher']['trace_rva'])+'\n')
    (root/'scope.bin').write_bytes(table)
    lines=[]
    for block in r['cleanups']+[r['restore']]:
     code=mapped_bytes(pe,base+block['rva'],block['size'])
     if sha(code)!=block['sha256'] or code!=(root/block['file']).read_bytes():raise ValueError('original code binding')
     if block in r['cleanups']:lines.append(str(block['rva'])+' '+block['file'])
     else:(root/'restore.bin').write_bytes(code)
    (root/'cleanup.list').write_text('\n'.join(lines)+'\n')
    (root/'active.txt').write_text('-1 2 0\n')
    target=r['restore_target_rva'];target_code=mapped_bytes(pe,base+target,15)
    if target_code[:1].hex()!=r['restore_target_first_byte']:raise ValueError('target binding')
    (root/'target.bin').write_bytes(target_code)
    def run(cmd,label,timeout):
     try:p=subprocess.run(cmd,capture_output=True,timeout=timeout)
     except subprocess.TimeoutExpired as e:
      (root/(label+'.stdout')).write_bytes(e.stdout or b'');(root/(label+'.stderr')).write_bytes(e.stderr or b'');raise
     (root/(label+'.stdout')).write_bytes(p.stdout);(root/(label+'.stderr')).write_bytes(p.stderr)
     if p.returncode:raise RuntimeError(label+': '+p.stderr.decode(errors='replace'))
    source=root/'unwind.rs'
    run([str(compiler),str(root),str(base),str(r['table_rva']),str(r['restore']['rva']),str(target),str(source)],'conversion',20)
    obs=r['observation']; saved=[obs['restore_eax'],11,12,13,32768,33024,16,17,target,514]
    current=[1,2,3,40,4096,8192,60,70,123,514]
    expected=[obs['restore_eax'],None,None,40,32768,33024,60,70,target,None]
    rust_array=lambda a:'['+','.join('None' if v is None else 'Some('+str(v)+')' for v in a)+']'
    harness='\nfn main(){let saved='+repr(saved)+';let current='+repr(current)+';let o=unwind(&[300,200,100],saved,current,0).unwrap();assert_eq!(o.trace,'+str(obs['trace'])+');assert_eq!(o.locals,vec![Some('+str(obs['selected'])+'),Some('+str(obs['outer'])+'),Some('+str(obs['inner'])+')]);assert_eq!(o.live,vec![true,false,false]);assert_eq!(o.restored,'+rust_array(expected)+');}\n'
    (root/'native.rs').write_text(source.read_text()+harness)
    run(['rustc','--edition=2021',str(root/'native.rs'),'-o',str(root/'native')],'rustc',60)
    p=execute([str(root/'native')],root/'native.stdout',root/'native.stderr',root/'native-launch',{'pe_sha256':r['pe_sha256']},{'exit':0},timeout=10)
    if p.returncode or (root/'native.stdout').read_bytes() or (root/'native.stderr').read_bytes():
        raise ValueError('native assertion execution failed or produced unexpected output')
    report=dict(kind='original authored dispatcher/cleanup helpers and separate manual restore slice; zero whole-PE pairs',
        pe_sha256=r['pe_sha256'],source_sha256=r['source_sha256'],
        scope_sha256=r['scope_table_sha256'],restore_sha256=r['restore']['sha256'],
        dispatcher=r['dispatcher'],
        rust_sha256=sha(source.read_bytes()),harness_sha256=sha((root/'native.rs').read_bytes()),
        native_sha256=sha((root/'native').read_bytes()),
        windows_observed=dict(trace=obs['trace'],locals=[obs['selected'],obs['outer'],obs['inner']],
            restore_eax=obs['restore_eax'],restore_stack_equal=obs['restore_stack_equal'],
            restore_frame_equal=obs['restore_frame_equal'],restore_target_rva=target),
        native_asserted=dict(trace=obs['trace'],locals=[obs['selected'],obs['outer'],obs['inner']],
            restored=expected,live=[True,False,False]),
        independent_slice_inputs=dict(saved=saved,current=current,initial_locals=[300,200,100],
            active_scopes=[-1,2,0],selected_frame=0),
        comparison_limits=[
            'Windows reports ESP/EBP equality only; 32768/33024 and the nonvolatile register vectors are independent native test inputs, not recorded Windows values.',
            'Target RVA is original Windows code; native execution stops at that target boundary without executing its instructions.',
            'Active scopes and selected frame are supplied at an explicit orchestration cut, not derived from translated Windows dispatcher instructions.',
            'Original authored Dispatch table selection, trace/local copying and parent-cursor writes are lifted; this does not recover Windows SEH frame selection.',
            'Windows SEH cleanup and later manual restoration are separate original observations composed by the native slice.'],
        limits=r['limits'])
    (root/'native-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        import unittest
        class EvidenceTests(unittest.TestCase):
            def setUp(self):
                self.frozen = json.loads((here/'unwind-frozen.json').read_text())
                self.observation = self.frozen['expected_observation'].copy()
                self.stdout = json.dumps(self.observation).encode()
                self.report = dict(exit=0,stdout_hex=self.stdout.hex(),stderr_hex='',
                    observation=self.observation.copy(),expected=self.frozen['expected_observation'].copy())
            def test_original_observation(self):
                self.assertEqual(verify_observation(self.report,self.stdout,b'',self.frozen),self.observation)
            def test_report_only_oracle_mutation(self):
                self.report['observation']['trace'] = 292
                with self.assertRaises(ValueError): verify_observation(self.report,self.stdout,b'',self.frozen)
            def test_consistent_output_and_report_still_need_frozen_oracle(self):
                self.observation['restore_eax'] = 78
                raw = json.dumps(self.observation).encode()
                self.report.update(observation=self.observation,stdout_hex=raw.hex())
                with self.assertRaises(ValueError): verify_observation(self.report,raw,b'',self.frozen)
            def test_report_expected_cannot_override_freeze(self):
                self.report['expected']['inner'] = 119
                with self.assertRaises(ValueError): verify_observation(self.report,self.stdout,b'',self.frozen)
            def test_true_is_not_observed_integer(self):
                self.observation['handled'] = True
                raw = json.dumps(self.observation).encode()
                self.report.update(observation=self.observation,stdout_hex=raw.hex())
                with self.assertRaises(ValueError): verify_observation(self.report,raw,b'',self.frozen)
            def test_failed_or_stderr_observation_rejected(self):
                self.report['exit'] = 1
                with self.assertRaises(ValueError): verify_observation(self.report,self.stdout,b'',self.frozen)
                self.report.update(exit=0,stderr_hex='78')
                with self.assertRaises(ValueError): verify_observation(self.report,self.stdout,b'x',self.frozen)
        unittest.main(argv=[sys.argv[0]])
    elif len(sys.argv) == 3 and sys.argv[1] == '--verify-only':
        report, _, _, _ = verify_evidence(Path(sys.argv[2]).resolve())
        print('Verified retained original Windows provenance:',report['pe_sha256'])
    else:
        main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
