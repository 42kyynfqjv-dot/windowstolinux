"""Independent malformed trace and owned-child cleanup evidence gates."""
import copy
import json
import unittest
from observe_unwind import SITE_NAMES,parse_events,summarize


def sample():
    rows=[]
    for sequence,site in enumerate(sorted(set(SITE_NAMES)-{16}),1):
        row=dict(kind='site',sequence=sequence,site=site,rva=site*16,image_base=0x400000,
            teb=0x700000,stack_limit=0x1000,stack_base=0x9000,fs_head=0x8000,
            eax=0,ecx=0,edx=0,ebx=17,esp=0x7000,ebp=0x7800,esi=19,edi=23,
            eflags=0x202,rtl_address=0x77001234,nlg=[0x19930520,0,0,0],
            chain=[dict(address=0x8000,words=[0xffffffff,0x77000000])],
            stack_words=[0]* (5 if site in (1,2) else 4 if site in (3,4,17) else 0),
            record_prefix=[0xe0424242,0,0,0] if site in (1,2) else [])
        if site==3:row['stack_words']=[0x8000,0x400040,0x7100,0]
        rows.append(row)
    rows.append(dict(kind='summary',success=True,cleanup_ok=True,child_exited=True,
        child_exit=0,events=100,hits=len(rows)))
    return rows,dict(sites=[dict(id=i,rva=i*16) for i in SITE_NAMES])


def encode(rows):return ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()


class ObserverEvidence(unittest.TestCase):
    def test_observed_unlink_order_is_not_assumed(self):
        rows,plan=sample()
        # A complete chain with the active record absent is retained as evidence,
        # not rejected because one disputed documentation page says otherwise.
        rows[0]['stack_words'][2]=0x8100
        parsed=parse_events(encode(rows),True,plan)
        report=summarize(parsed,plan)
        self.assertEqual(report['callbacks'][0]['establisher'],0x8100)
        self.assertEqual(report['callbacks'][0]['chain'][0]['address'],0x8000)
        self.assertEqual(report['rtl_arguments']['target_ip'],0x400040)

    def test_cleanup_failure_control_requires_reaped_child(self):
        rows=[dict(kind='summary',success=False,cleanup_ok=True,child_exited=True,
            child_exit=125,events=4,hits=1)]
        parse_events(encode(rows),False)
        for key,value in [('cleanup_ok',False),('child_exited',False),('child_exit',0),('success',True)]:
            bad=copy.deepcopy(rows);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):parse_events(encode(bad),False)
        with self.assertRaises(ValueError):parse_events(encode(rows[:-1]),False)

    def test_tampered_sites_and_incomplete_chain_reject(self):
        rows,plan=sample()
        mutations=[lambda r:r[0].update(rva=999),lambda r:r[0].update(site=99),
            lambda r:r[0]['chain'][0].update(address=0x8004),
            lambda r:r[0]['chain'][0]['words'].__setitem__(0,0x8100),
            lambda r:r[0].update(stack_base=0x8004),
            lambda r:r[0].update(record_prefix=[]),lambda r:r[0].update(eax=True)]
        for i,mutate in enumerate(mutations):
            bad=copy.deepcopy(rows);mutate(bad)
            with self.subTest(mutation=i),self.assertRaises(ValueError):parse_events(encode(bad),True,plan)

    def test_false_completion_and_changed_target_reject(self):
        rows,plan=sample()
        for mutate in [lambda r:r[-1].update(hits=1),lambda r:r.pop(2),
                       lambda r:r.append(dict(kind='summary')),lambda r:r[0].update(kind='invented')]:
            bad=copy.deepcopy(rows);mutate(bad)
            with self.assertRaises(ValueError):parse_events(encode(bad),True,plan)
        rows[2]['stack_words'][1]+=1
        with self.assertRaises(ValueError):summarize(rows,plan)


class ActualManifestParser(unittest.TestCase):
    def test_truncated_final_records_reject_in_original_c_parser(self):
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path
        cc=shutil.which('cc')
        if cc is None:self.skipTest('portable C compiler unavailable; Windows observer remains required')
        source=(Path(__file__).resolve().parents[3]/'tools'/'observe_unwind.c').read_text()
        function=source[source.index('static BOOL manifest('):source.index('static BOOL module(')]
        # Compile the actual side-effect-free parser, with only Windows integer
        # typedefs replaced for this host; no observer/debugger path executes.
        stub='''#include <stdio.h>
#include <string.h>
typedef unsigned long DWORD;typedef unsigned char BYTE;typedef int BOOL;typedef unsigned long long ULONGLONG;
#define TRUE 1
#define FALSE 0
#define MAX_SITES 24
struct Site { DWORD rva,address,id;BYTE byte;BOOL patched;};
static struct Site sites[MAX_SITES];static unsigned site_count;
static DWORD image_size,handler_rva,nested_rva,nlg_rva,rtl_iat_rva;
'''+function+'\nint main(int argc,char **argv){return argc==2 && manifest(argv[1])?0:125;}\n'
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);c=root/'parser.c';c.write_text(stub);binary=root/'parser'
            subprocess.run([cc,'-std=c99','-Wall','-Wextra',str(c),'-o',str(binary)],check=True,capture_output=True)
            valid='4096 16 32 64 80\n1 16 85\n'
            cases=[(valid,0),(valid+'2',125),(valid+'2 32',125),(valid+'2 32\n',125),
                   (valid+'2 32 85 trailing\n',125),(valid+'2 32 85',125),(valid+'2 32 85\n',0)]
            for index,(contents,expected) in enumerate(cases):
                path=root/f'case{index}';path.write_text(contents)
                with self.subTest(index=index):
                    self.assertEqual(subprocess.run([str(binary),str(path)],capture_output=True).returncode,expected)

if __name__=='__main__':unittest.main()
