"""Malformed retained-observation gates; these tests do not execute Windows."""
import copy
import json
import unittest
from observe_stdio import SITES,CASES,parse_events,summarize,summarize_wrapper


def encoded(rows):return ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()

def sample(label='baseline'):
    expected=CASES[label];base=0x400000;stdout=base+0x1c0b8
    # Independent event ordering exercises delayed flushing after Main return.
    order=[1,16,17,10,11,12,13,18,19,20,2,3,8,15,10,11,4,5,6,7]
    if expected['error']:order +=[14]
    order +=[9,12,13]
    rows=[];write_calls=0
    for number,site in enumerate(order,1):
        words=[0x8000,0x8000,0,0x42,1,0,0,0,0,0xffffffff,0,0,0,0]
        if site>=4 and number>=order.index(4)+1:write_calls=1
        if site in (9,14) and expected['error']:words[3]|=16
        args=[5,0x6000,276,0x5ff0,0] if site==4 else [0,stdout] if site in (8,9) else [stdout+32] if site in (10,12) else []
        eax=expected['count']
        if site==5:eax=0 if label=='invalid-handle' else 1
        elif site==7:eax=expected['logical']
        elif site==9:eax=expected['flush']
        elif site==2:eax=275
        elif site==3:eax=0
        row=dict(kind='site',sequence=number,site=site,rva=SITES[site][1],image_base=base,
            stack_limit=0x1000,stack_base=0x10000,eax=eax,ecx=0,edx=0,ebx=0,
            esp=0x7020 if site==5 else 0x700c if site==4 else 0x7000,ebp=0x7800,esi=0,edi=0,eflags=0x202,
            writefile_address=0x77001000,stdout_address=stdout,stream_argument=stdout if site in (8,9,10,11,12,13) else 0,
            count_cell=0x5ff0,count_value=expected['count'],write_calls=write_calls,
            stream_words=words,arguments=args,text_result=expected['text_result'] if site==6 else [],request_hex=('41'*276) if site==4 else '')
        row.update(thread_head=0x9000,wrapper_cookie=0,wrapper_words=[])
        if site in (16,17,18,19,20):
            row.update(eax=275,ebx=31,ebp=0x7800,esi=47,edi=59)
        if site in (17,18):
            cookie=0x12345678
            row.update(esp=0x7000-48,ebp=0x7000-4,thread_head=0x7000-20,wrapper_cookie=cookie,
                wrapper_words=[cookie^0x6ffc,59,47,31,0,0x6fd0,0,0x9000,0x402210,cookie^0x41b400,0xfffffffe,0x7800,0x4064d3])
        if site==20:row['esp']=0x7010
        rows.append(row)
        if site==4 and expected['mode']:
            if expected['mode']<4:rows.append(dict(kind='injection',mode=expected['mode'],count=expected['count'],api_executed=False,physical_bytes_written=0))
            else:rows.append(dict(kind='injection',mode=4,api_executed=True,argument='INVALID_HANDLE_VALUE'))
    rows.append(dict(kind='interval-complete',last_site=13,hits=len(order),breakpoints_restored=True,trap_flag_cleared=True))
    rows.append(dict(kind='summary',success=True,cleanup_ok=True,child_exited=True,child_exit=0,interval_complete=True,
        breakpoints_restored=True,events=80,hits=len(order)))
    plan=dict(sites=[dict(id=i,rva=SITES[i][1]) for i in SITES],stdout_rva=stdout-base,original_stdout_hex='41'*276)
    return rows,plan


class StdioObservationGates(unittest.TestCase):
    def test_real_and_scripted_cases_remain_distinct(self):
        for label in CASES:
            with self.subTest(label=label):
                rows,plan=sample(label);parsed=parse_events(encoded(rows),label,plan)
                result=summarize(parsed,label,plan)
                self.assertEqual(result['main_return'],0)
                self.assertLess(result['order']['main_return'],result['order']['writefile'])
                self.assertEqual(result['api_class'],CASES[label]['api'])
    def test_wrapper_actual_saved_words_fs_and_cleanup_are_not_assumed(self):
        rows,_=sample();sites=[r for r in rows if r['kind']=='site']
        self.assertEqual(summarize_wrapper(sites)['frame_offsets'],[-48,-4,-20])
        for site,key,value in [(17,'esp',0x7000),(18,'thread_head',0x9000),(19,'ebx',0),
                              (20,'esp',0x7004),(19,'eflags',0x203),(20,'eax',0)]:
            bad=copy.deepcopy(sites);next(r for r in bad if r['site']==site)[key]=value
            with self.subTest(site=site,key=key),self.assertRaises(ValueError):summarize_wrapper(bad)
        for index in [0,1,2,3,5,7,8,9,10,11]:
            bad=copy.deepcopy(sites);next(r for r in bad if r['site']==17)['wrapper_words'][index]^=1
            with self.subTest(index=index),self.assertRaises(ValueError):summarize_wrapper(bad)

    def test_injected_success_cannot_claim_real_os_write(self):
        rows,plan=sample('short-seven');injection=next(r for r in rows if r['kind']=='injection');injection['api_executed']=True
        with self.assertRaises(ValueError):parse_events(encoded(rows),'short-seven',plan)
        rows,plan=sample('baseline');rows.insert(-1,dict(kind='injection',mode=1,count=7,api_executed=False,physical_bytes_written=0))
        with self.assertRaises(ValueError):parse_events(encoded(rows),'baseline',plan)
    def test_original_short_write_cannot_silently_retry(self):
        rows,plan=sample('short-seven');row=copy.deepcopy(next(r for r in rows if r.get('site')==4));rows.insert(-2,row)
        with self.assertRaises(ValueError):parse_events(encoded(rows),'short-seven',plan)
    def test_missing_reset_error_or_unlock_rejects(self):
        for mutation in ('error','reset','unlock'):
            rows,plan=sample('short-seven')
            if mutation=='error':next(r for r in rows if r.get('site')==9)['stream_words'][3]&=~16
            elif mutation=='reset':next(r for r in rows if r.get('site')==9)['stream_words'][2]=4
            else:
                for r in rows:
                    if r.get('site')==13:r['stream_words'][10]=1
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):summarize(rows,'short-seven',plan)
    def test_instruction_and_stack_receipts_reject_tampering(self):
        for key,value in [('rva',1),('eax',True),('stdout_address',0),('stream_words',[]),('stack_limit',0x9000)]:
            rows,plan=sample();rows[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):parse_events(encoded(rows),'baseline',plan)
    def test_cleanup_failure_requires_owned_child_reaped(self):
        rows=[dict(kind='summary',success=False,cleanup_ok=True,child_exited=True,child_exit=125,interval_complete=False,
            breakpoints_restored=True,events=8,hits=1)]
        parse_events(encoded(rows),'baseline',{},True)
        for key,value in [('cleanup_ok',False),('child_exited',False),('breakpoints_restored',False),('child_exit',0)]:
            bad=copy.deepcopy(rows);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):parse_events(encoded(bad),'baseline',{},True)
    def test_interval_must_clear_breakpoints_and_tf(self):
        rows,plan=sample();rows[-2]['trap_flag_cleared']=False
        with self.assertRaises(ValueError):parse_events(encoded(rows),'baseline',plan)
        rows,plan=sample();rows.pop(-2)
        with self.assertRaises(ValueError):parse_events(encoded(rows),'baseline',plan)

if __name__=='__main__':unittest.main()
