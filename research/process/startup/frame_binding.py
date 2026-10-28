"""Bind original authored frame/filter fragments; this does not prove startup.

COFF identifies complete original functions and EH4 tables. Retained dumpbin
instruction records are accepted only when their bytes cover and match the PE;
production independently decodes every admitted fragment. Unexecuted calls and
registration effects remain explicit cuts, never silently removed from a path.
"""
import hashlib
import json
from pathlib import Path
import re
import struct

from coff_binding import bind_function, coff, cut, import_at_iat, pe_sections, u32
from inventory import mapped_bytes


def sha(data):
    return hashlib.sha256(data).hexdigest()


def instructions(text, image):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-fA-F]{8}):\s+(.*)$',line)
        if match:
            tokens = match[2].split()
            count = 0
            while count < len(tokens) and re.fullmatch('[0-9a-fA-F]{2}',tokens[count]):
                count += 1
            if not count:
                raise ValueError('missing original disassembly bytes')
            rows.append(dict(va=int(match[1],16), raw=bytearray.fromhex(' '.join(tokens[:count])),
                             text=' '.join(tokens[count:])))
        elif rows and re.fullmatch(r'\s+(?:[0-9a-fA-F]{2}\s*)+',line):
            rows[-1]['raw'].extend(bytes.fromhex(line.strip()))
    if not rows or len(rows) > 200000:
        raise ValueError('disassembly evidence budget')
    base,_ = pe_sections(image)
    result = {}
    for row in rows:
        code = bytes(row['raw'])
        if not 1 <= len(code) <= 15 or mapped_bytes(image,row['va'],len(code)) != code:
            raise ValueError('disassembly differs from retained original PE')
        rva = row['va']-base
        if rva in result:
            raise ValueError('duplicate original instruction address')
        result[rva] = dict(rva=rva,size=len(code),code_hex=code.hex(),text=row['text'])
    return result


def function_rows(function, index):
    cursor = function['rva']
    end = cursor+function['size']
    rows = []
    while cursor < end:
        if cursor not in index:
            raise ValueError('original function instruction coverage gap')
        row = index[cursor]
        if cursor+row['size'] > end:
            raise ValueError('instruction crosses original COFF function boundary')
        rows.append(row)
        cursor += row['size']
    return rows


def fragment(function, rows, start, end, name, role):
    boundaries = {row['rva'] for row in rows} | {function['rva']+function['size']}
    if start not in boundaries or end not in boundaries or not start < end:
        raise ValueError('fragment does not cover complete original instructions')
    selected = [row for row in rows if start <= row['rva'] < end]
    raw = b''.join(bytes.fromhex(row['code_hex']) for row in selected)
    if len(raw) != end-start:
        raise ValueError('fragment coverage is not contiguous')
    return dict(name=name,rva=start,size=len(raw),code_hex=raw.hex(),sha256=sha(raw),
                file=name+'.bin',role=role,instructions=selected)


def symbol_in_section(symbols,name,section):
    found = [s for s in symbols.values() if s['name'] == name and s['section'] == section]
    if len(found) != 1:
        raise ValueError('missing or ambiguous original local target symbol')
    return found[0]


def bind_eh4(obj,image,function,symbols,sections):
    base,_ = pe_sections(image)
    name = '__sehtable$'+function['symbol']
    references = [r for r in function['relocations'] if r['symbol'] == name]
    if len(references) != 1 or references[0]['kind'] != 6 or references[0]['addend'] != 0:
        raise ValueError('original frame lacks unique EH4 table reference')
    found = [s for s in symbols.values() if s['name'] == name]
    if len(found) != 1 or found[0]['value'] != 0 or not 1 <= found[0]['section'] <= len(sections):
        raise ValueError('unsupported original EH4 data symbol')
    section = sections[found[0]['section']-1]
    if section['flags'] & 0xa0000000 or not 28 <= section['size'] <= 16+12*32 or (section['size']-16)%12:
        raise ValueError('EH4 table must be bounded read-only data')
    raw = cut(obj,section['start'],section['size'])
    va = references[0]['target_va']
    linked = mapped_bytes(image,va,len(raw))
    mask = bytearray(b'\1'*len(raw))
    targets = []
    for reloc in section['relocs']:
        offset = reloc['offset']
        if reloc['kind'] != 6 or offset < 20 or offset+4 > len(raw) or offset%12 not in (8,0) or mask[offset:offset+4] != b'\1'*4:
            raise ValueError('unsupported EH4 target relocation')
        local = symbol_in_section(symbols,reloc['symbol'],function['object_section'])
        expected = base+function['rva']+local['value']+u32(raw,offset)
        if expected > 0xffffffff or u32(linked,offset) != expected:
            raise ValueError('EH4 target not bound to original local symbol')
        targets.append(dict(offset=offset,symbol=reloc['symbol'],target_rva=expected-base))
        mask[offset:offset+4] = b'\0'*4
    if any(mask[i] and raw[i] != linked[i] for i in range(len(raw))):
        raise ValueError('EH4 nonrelocated data differs from original object')
    header = list(struct.unpack('<iiii',linked[:16]))
    entries = []
    for i in range((len(linked)-16)//12):
        parent,filter_va,handler_va = struct.unpack_from('<iII',linked,16+i*12)
        if parent < -2 or parent == -1 or parent >= i:
            raise ValueError('unsupported EH4 scope-parent ordering')
        for value,offset in ((filter_va,20+i*12),(handler_va,24+i*12)):
            if value and not any(t['offset'] == offset and t['target_rva'] == value-base for t in targets):
                raise ValueError('EH4 pointer lacks original relocation binding')
        entries.append(dict(index=i,parent=parent,filter_rva=filter_va-base if filter_va else None,
                            handler_rva=handler_va-base if handler_va else None))
    return dict(symbol=name,rva=va-base,size=len(linked),code_hex=linked.hex(),sha256=sha(linked),
                file=function['symbol'][1:]+'-eh4.bin',header=header,rows=entries,relocations=targets)


def through_ret(function,rows,start,name,role):
    tail = [r for r in rows if r['rva'] >= start]
    if not tail or tail[0]['rva'] != start:
        raise ValueError('EH4 target is not an original instruction boundary')
    for row in tail:
        if row['code_hex'] == 'c3':
            return fragment(function,rows,start,row['rva']+1,name,role)
    raise ValueError('bounded original funclet has no RET')


def immediate_frame_stores(rows):
    stores = []
    for row in rows:
        code = bytes.fromhex(row['code_hex'])
        if len(code) == 7 and code[:2] == b'\xc7\x45':
            offset = struct.unpack('<b',code[2:3])[0]
            value = u32(code,3)
        elif len(code) == 10 and code[:2] == b'\xc7\x85':
            offset = struct.unpack('<i',code[2:6])[0]
            value = u32(code,6)
        else:
            continue
        stores.append(dict(instruction_rva=row['rva'],frame_offset=offset,value=value))
    return stores


def call_binding(image,function,row):
    raw = bytes.fromhex(row['code_hex'])
    if raw[:1] == b'\xe8' and len(raw) == 5:
        operand,kind = 1,0x14
    elif raw[:2] == b'\xff\x15' and len(raw) == 6:
        operand,kind = 2,6
    else:
        raise ValueError('unsupported original call evidence')
    offset = row['rva']-function['rva']+operand
    bindings = [r for r in function['relocations'] if r['offset'] == offset and r['kind'] == kind and r['addend'] == 0]
    if len(bindings) != 1:
        raise ValueError('original call has no unique COFF provenance')
    binding = bindings[0]
    base,_ = pe_sections(image)
    result = dict(rva=row['rva'],code_hex=row['code_hex'],symbol=binding['symbol'],
                  target_rva=binding['target_va']-base)
    if kind == 6:
        result['import'] = list(import_at_iat(image,result['target_rva']))
    return result


def handler_fragments(image,index,bound):
    """Retain a closed direct-helper CFG and explicit borrowed handler cuts."""
    base,sections = pe_sections(image)
    handlers = [r['target_va'] for f in bound.values() for r in f['relocations']
                if r['symbol'] == '__except_handler4' and r['kind'] == 6 and r['addend'] == 0]
    if len(handlers) != 3 or len(set(handlers)) != 1:
        raise ValueError('original frames disagree about linked exception handler')
    handler = handlers[0]-base
    # Original linked handler's first direct call receives ExceptionCode. This
    # binds a measured call edge, not a claim that other handler effects close.
    leading = []
    cursor = handler
    for _ in range(64):
        if cursor not in index:
            raise ValueError('missing original handler instruction')
        row = index[cursor]
        leading.append(row)
        code = bytes.fromhex(row['code_hex'])
        if code[:1] == b'\xe8':
            if len(code) != 5:
                raise ValueError('invalid original helper call')
            helper = cursor+5+struct.unpack('<i',code[1:])[0]
            call_rva = cursor
            break
        if code[:1] in (b'\xc3',b'\xc2',b'\xe9',b'\xeb',b'\xff'):
            # FF33 is a memory PUSH of the event code, not an indirect transfer.
            if code != b'\xff\x33':
                raise ValueError('unexpected control flow before original helper call')
        cursor += row['size']
    else:
        raise ValueError('original handler prefix budget')
    # Reachable instruction closure rather than first RET: this helper has five
    # returns and an MXCSR-dependent branch that cannot be silently discarded.
    pending = [helper]
    visited = {}
    while pending:
        at = pending.pop()
        if at in visited:
            continue
        if not helper <= at < helper+512 or at not in index or len(visited) >= 128:
            raise ValueError('original event helper graph exceeds evidence bounds')
        row = index[at]
        visited[at] = row
        raw = bytes.fromhex(row['code_hex'])
        after = at+len(raw)
        if raw == b'\xc3':
            continue
        if raw[0] in (0xe8,0xff,0xc2):
            raise ValueError('event helper has unsupported call/indirect edge')
        if raw[0] == 0xeb:
            pending.append(after+struct.unpack('<b',raw[1:])[0])
        elif raw[0] == 0xe9:
            pending.append(after+struct.unpack('<i',raw[1:])[0])
        elif 0x70 <= raw[0] <= 0x7f:
            pending.extend([after,after+struct.unpack('<b',raw[1:])[0]])
        elif raw[:1] == b'\x0f' and len(raw) >= 2 and 0x80 <= raw[1] <= 0x8f:
            pending.extend([after,after+struct.unpack('<i',raw[2:])[0]])
        else:
            pending.append(after)
    helper_end = max(r['rva']+r['size'] for r in visited.values())
    helper_rows = sorted(visited.values(),key=lambda row:row['rva'])
    pseudo = dict(rva=helper,size=helper_end-helper)
    normalizer = fragment(pseudo,helper_rows,helper,helper_end,'event-normalizer',
        'complete original direct-helper CFG; feature/MXCSR reads and all branch effects retained, not yet proved')
    feature_loads = [r for r in helper_rows if len(bytes.fromhex(r['code_hex'])) == 7 and r['code_hex'].startswith('833d')]
    if len(feature_loads) != 1:
        raise ValueError('event normalizer feature-word load changed')
    feature_word = u32(bytes.fromhex(feature_loads[0]['code_hex']),2)
    owners = [s for s in sections if base+s['rva'] <= feature_word and feature_word+4 <= base+s['rva']+s['virtual']]
    if len(owners) != 1 or not owners[0]['flags'] & 0x80000000 or owners[0]['flags'] & 0x20000000:
        raise ValueError('event normalizer feature word is not unique module data')
    # The original installer writes two pointer cells in the handler's live
    # frame, then installs their address at establisher-4. Its preceding calls
    # are separately recorded as unproved, not skipped by an execution proof.
    installer_bytes = bytes.fromhex('8945e48b45108945e88d45e48943fc')
    window = mapped_bytes(image,base+handler,256)
    offset = window.find(installer_bytes)
    if offset == -1 or window.find(installer_bytes,offset+1) != -1:
        raise ValueError('original exception-pointer installer not unique')
    installer_start = handler+offset
    installer_end = installer_start+len(installer_bytes)
    window_rows = []
    cursor = handler
    while cursor < installer_end:
        if cursor not in index:
            raise ValueError('handler prefix instruction gap')
        row = index[cursor]
        window_rows.append(row)
        cursor += row['size']
    pseudo = dict(rva=handler,size=installer_end-handler)
    prefix = fragment(pseudo,window_rows,handler,installer_start,'handler-before-pair',
        'NOT EXECUTED: event normalization, cookie validation, context helper, flag/record reads and branch')
    installer = fragment(pseudo,window_rows,installer_start,installer_end,'exception-pair-installer',
        'original pointer-cell writes at an explicit handler-entry cut; live ownership/preconditions still required')
    calls = []
    for row in window_rows:
        raw = bytes.fromhex(row['code_hex'])
        if raw[:1] == b'\xe8':
            calls.append(dict(call_rva=row['rva'],target_rva=row['rva']+5+struct.unpack('<i',raw[1:])[0]))
    combined = fragment(pseudo,window_rows,handler,installer_end,'handler-through-installer',
        'complete original prefix through pair installation; helper effects and flags branch require composed proof')
    return [normalizer,prefix,installer,combined], dict(
        handler_rva=handler,normalizer_call_rva=call_rva,normalizer_rva=helper,
        feature_word_rva=feature_word-base,feature_word_value='unobserved runtime value; initialized ownership still required',
        prefix_calls=calls,installer_rva=installer_start,installer_end_rva=installer_end,
        installer_fields=dict(handler_pair_record=-28,handler_pair_context=-24,
            handler_context_argument=16,establisher_pair_pointer=-4,
            owner_ebp_from_establisher=16,owner_pair_pointer=-20,exception_code_offset=0),
        unresolved='Event-code transformation, cookie/context helper effects, exception flags, live pointer ownership and execution ordering require production proof')


def linked_cfg(image,index,entry,name,external_jumps=()):
    """Retain all local direct edges; calls and declared tail exits stay effects."""
    pending=[entry];visited={};calls=[];tails=[];traps=[]
    while pending:
        at=pending.pop()
        if at in visited:continue
        if not entry <= at < entry+512 or at not in index or len(visited)>=256:
            raise ValueError('linked helper graph leaves bounded original range')
        row=index[at];visited[at]=row;raw=bytes.fromhex(row['code_hex']);after=at+len(raw)
        if raw==b'\xc3' or (raw[0]==0xc2 and len(raw)==3):continue
        if raw[0]==0xe8:
            calls.append(dict(call_rva=at,target_rva=after+struct.unpack('<i',raw[1:])[0]))
            pending.append(after)
        elif raw[0] in (0xe9,0xeb):
            delta=struct.unpack('<i' if raw[0]==0xe9 else '<b',raw[1:])[0]
            target=after+delta
            if target in external_jumps:tails.append(dict(jump_rva=at,target_rva=target))
            else:pending.append(target)
        elif 0x70<=raw[0]<=0x7f:
            pending.extend([after,after+struct.unpack('<b',raw[1:])[0]])
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:
            pending.extend([after,after+struct.unpack('<i',raw[2:])[0]])
        elif raw[:1]==b'\xff':
            raise ValueError('unbound linked-helper indirect control effect')
        elif raw==b'\xcd\x29':
            traps.append(dict(rva=at,kind='INT 29; failure contract required'))
            # Retaining fallthrough is conservative evidence, not a claim the
            # Windows fail-fast trap returns successfully.
            pending.append(after)
        else:pending.append(after)
    end=max(row['rva']+row['size'] for row in visited.values())
    all_rows=[];cursor=entry
    while cursor<end:
        if cursor not in index:raise ValueError('linked helper byte coverage gap')
        row=index[cursor];all_rows.append(row);cursor+=row['size']
    block=fragment(dict(rva=entry,size=end-entry),all_rows,entry,end,name,
        'complete bounded local instruction envelope; call/tail/trap effects require separate proof')
    block.update(direct_calls=calls,external_tail_edges=tails,traps=traps)
    return block


def module_word(image,va,role):
    base,sections=pe_sections(image)
    owners=[s for s in sections if base+s['rva']<=va and va+4<=base+s['rva']+s['virtual']]
    if len(owners)!=1:raise ValueError('module word has ambiguous/incomplete virtual ownership')
    owner=owners[0];offset=va-base-owner['rva']
    backed=max(0,min(4,owner['size']-offset))
    prefix=cut(image,owner['start']+offset,backed) if backed else b''
    initial=prefix+b'\0'*(4-backed)
    return dict(rva=va-base,size=4,section_rva=owner['rva'],section_flags=owner['flags'],
        file_backed_bytes=backed,file_prefix_hex=prefix.hex(),zero_fill_bytes=4-backed,
        image_initial_word=struct.unpack('<I',initial)[0],role=role,
        runtime_value='unobserved; image initial bytes are not a proof of post-startup state')


def connected_helper_evidence(image,index,bound,frames,blocks,handler,observation):
    base,_=pe_sections(image);main=bound['_main'];main_rows=function_rows(main,index)
    by_name={b['name']:b for b in blocks}
    memset_calls=[r for r in main['relocations'] if r['symbol']=='_memset' and r['kind']==0x14 and r['addend']==0]
    if len(memset_calls)!=1:raise ValueError('missing unique original memset call')
    memset=linked_cfg(image,index,memset_calls[0]['target_va']-base,'original-memset')
    memset_words=[]
    for row in memset['instructions']:
        raw=bytes.fromhex(row['code_hex'])
        if raw[:3]==b'\x0f\xba\x25' and len(raw)==8:
            va=u32(raw,3)
            if va not in [base+w['rva'] for w in memset_words]:
                memset_words.append(module_word(image,va,'memset CPU-dispatch feature word'))
    if len(memset_words)!=2:raise ValueError('original memset feature inventory changed')
    prefix_calls=handler['prefix_calls']
    if len(prefix_calls)!=3:raise ValueError('original handler prefix dependency inventory changed')
    guard_entry=prefix_calls[1]['target_rva'];context_entry=prefix_calls[2]['target_rva']
    guard_rows=[];cursor=guard_entry
    for _ in range(64):
        row=index.get(cursor)
        if row is None:raise ValueError('guard helper instruction gap')
        guard_rows.append(row);raw=bytes.fromhex(row['code_hex'])
        if raw[0]==0xe8:
            security_entry=cursor+len(raw)+struct.unpack('<i',raw[1:])[0]
            break
        cursor+=row['size']
    else:raise ValueError('guard helper has no bounded security call')
    guard=linked_cfg(image,index,guard_entry,'original-guard-validator',[security_entry])
    # Security check is CMP/JNE/RET plus a failure tail edge. Derive the failure
    # destination from original instructions, retaining that external obligation.
    cursor=security_entry
    for _ in range(16):
        row=index.get(cursor)
        if row is None:raise ValueError('security helper instruction gap')
        raw=bytes.fromhex(row['code_hex'])
        if raw[0]==0xe9:
            failure=cursor+len(raw)+struct.unpack('<i',raw[1:])[0]
            break
        cursor+=row['size']
    else:raise ValueError('security helper failure edge not bounded')
    security=linked_cfg(image,index,security_entry,'original-security-check',[failure])
    cookie_refs=[r['target_va'] for f in bound.values() for r in f['relocations'] if r['symbol']=='___security_cookie']
    first=bytes.fromhex(security['instructions'][0]['code_hex'])
    if len(set(cookie_refs))!=1 or len(first)!=6 or first[:2]!=b'\x3b\x0d' or u32(first,2)!=cookie_refs[0]:
        raise ValueError('security comparison cookie provenance differs from frames')
    context=linked_cfg(image,index,context_entry,'original-context-check')
    selectors=[r for r in context['instructions'] if r['code_hex'].startswith('813d') and r['size']==10]
    if len(selectors)!=1:raise ValueError('context check selector inventory changed')
    raw=bytes.fromhex(selectors[0]['code_hex']);selector_va=u32(raw,2);stub_va=u32(raw,6)
    stub=index.get(stub_va-base)
    if stub is None or stub['code_hex']!='c20000':raise ValueError('context selector comparison stub changed')
    selector=module_word(image,selector_va,'context-check runtime dispatch pointer')
    selector.update(comparison_stub_rva=stub_va-base,comparison_stub_hex=stub['code_hex'])
    # Include the complete original selected landing, context-field setup,
    # manual Restore call, abandoned return sentinel and three capture stores.
    landing=by_name['main-selected-handler-0'];target=observation['restore_target_rva']
    cursor=target;capture=[]
    for prefix in [b'\x89\x85',b'\x89\xa5',b'\x89\xad']:
        row=index.get(cursor)
        if row is None:raise ValueError('missing manual restore capture instruction')
        raw=bytes.fromhex(row['code_hex'])
        if len(raw)!=6 or raw[:2]!=prefix:raise ValueError('manual restoration capture sequence changed')
        capture.append(row);cursor+=6
    continuation=fragment(main,main_rows,landing['rva'],cursor,'selected-through-capture',
        'complete original landing, context setup, nonlocal Restore call and capture; no omitted call in this interval')
    restore_calls=[r for r in main['relocations'] if r['symbol']=='_Restore' and r['kind']==0x14]
    if len(restore_calls)!=1:raise ValueError('manual restoration call provenance changed')
    continuation['restore_call_rva']=main['rva']+restore_calls[0]['offset']-1
    continuation['restore_target_rva']=target
    continuation['capture_end_rva']=cursor
    continuation['capture_stores']=[dict(rva=r['rva'],frame_offset=struct.unpack('<i',bytes.fromhex(r['code_hex'])[2:])[0],
        register=reg) for r,reg in zip(capture,['EAX','ESP','EBP'])]
    header=u32(image,60)
    directory_rva,directory_size=struct.unpack('<II',cut(image,header+24+96+10*8,8))
    if not directory_rva or not 4<=directory_size<=512:raise ValueError('load-config declared range unsupported')
    declared=mapped_bytes(image,base+directory_rva,directory_size)
    embedded_size=u32(declared,0)
    if not directory_size<=embedded_size<=512:raise ValueError('load-config embedded extent unsupported')
    embedded=mapped_bytes(image,base+directory_rva,embedded_size)
    configuration=dict(rva=directory_rva,declared_directory_size=directory_size,embedded_size=embedded_size,
        declared_bytes_hex=declared.hex(),embedded_bytes_hex=embedded.hex(),
        dll_characteristics=struct.unpack('<H',cut(image,header+24+70,2))[0],
        interpretation='Bytes beyond directory size are recorded as embedded image evidence, not asserted loader-consumed fields')
    return [memset,guard,security,context,continuation],dict(
        memset_call_rva=main['rva']+memset_calls[0]['offset']-1,
        memset_feature_words=memset_words,guard_entry_rva=guard_entry,
        security_entry_rva=security_entry,security_failure_target_rva=failure,
        cookie_word=module_word(image,cookie_refs[0],'security cookie read by original checker'),
        context_selector=selector,load_configuration=configuration,
        failure_obligation='Security mismatch tail target and INT29 effects are retained, not treated as successful returns',
        context_obligation='FS:[0x18] TEB identity, stack bounds and initialized CONTEXT.ESP require owned runtime state',
        memset_obligation='All scalar/REP/SIMD paths and CPU-dispatch feature values require proven effects or an explicit independently validated effect contract')


def dispatch_cfg(image,index,entry,name):
    """Bound complete local CFG bytes, retaining every call/indirect obligation.

    This is evidence extraction, not admission: unknown callees/indirect targets
    and trap paths remain explicitly unresolved. Production must decode again.
    """
    pending=[entry];visited={};calls=[];indirect=[];branches=[];returns=[];traps=[]
    while pending:
        at=pending.pop()
        if at in visited:continue
        if not entry<=at<entry+2048 or at not in index or len(visited)>=512:
            raise ValueError('dispatch evidence graph leaves bounded original body')
        row=index[at];visited[at]=row;raw=bytes.fromhex(row['code_hex']);after=at+len(raw)
        if raw==b'\xc3' or (raw[0]==0xc2 and len(raw)==3):
            returns.append(dict(rva=at,pop_bytes=0 if len(raw)==1 else struct.unpack('<H',raw[1:])[0]));continue
        if raw==b'\xcc':
            traps.append(dict(rva=at,kind='INT3 terminal failure edge; not successful continuation'));continue
        if raw[0]==0xe8:
            calls.append(dict(call_rva=at,target_rva=after+struct.unpack('<i',raw[1:])[0]));pending.append(after)
        elif raw[0] in (0xe9,0xeb):
            target=after+struct.unpack('<i' if raw[0]==0xe9 else '<b',raw[1:])[0]
            branches.append(dict(rva=at,target_rva=target,conditional=False));pending.append(target)
        elif 0x70<=raw[0]<=0x7f or (raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f):
            target=after+(struct.unpack('<b',raw[1:])[0] if raw[0]!=0x0f else struct.unpack('<i',raw[2:])[0])
            branches.append(dict(rva=at,target_rva=target,conditional=True));pending.extend([after,target])
        elif raw[0]==0xff and (raw[1]>>3)&7 in (2,4):
            call=(raw[1]>>3)&7==2
            effect=dict(rva=at,kind='call' if call else 'jump',code_hex=raw.hex())
            if raw[:2]==b'\xff\x15':
                base,_=pe_sections(image);slot=u32(raw,2);effect['slot_rva']=slot-base
                try:effect['import']=list(import_at_iat(image,slot-base))
                except ValueError:effect['import']=None
            indirect.append(effect)
            if call:pending.append(after)
        elif raw[0] in (0xe0,0xe1,0xe2,0xe3,0x9a,0xea,0xca,0xcb,0xcf,0xcd):
            raise ValueError('dispatch evidence unsupported control encoding')
        else:pending.append(after)
    end=max(r['rva']+r['size'] for r in visited.values());cursor=entry;rows=[]
    while cursor<end:
        if cursor not in index:raise ValueError('dispatch original instruction coverage gap')
        rows.append(index[cursor]);cursor+=index[cursor]['size']
    block=fragment(dict(rva=entry,size=end-entry),rows,entry,end,name,
        'complete bounded original instruction envelope; no proof of external calls, indirect effects or Windows dispatcher contract')
    block.update(direct_calls=sorted(calls,key=lambda x:x['call_rva']),
        indirect_effects=sorted(indirect,key=lambda x:x['rva']),branches=sorted(branches,key=lambda x:x['rva']),
        return_sites=sorted(returns,key=lambda x:x['rva']),trap_sites=sorted(traps,key=lambda x:x['rva']))
    return block


def dispatch_evidence(image,index,bound,handler):
    """Derive graph entry identities from the already COFF-bound handler path."""
    base,_=pe_sections(image)
    full=dispatch_cfg(image,index,handler['handler_rva'],'original-handler-complete')
    known={c['target_rva'] for c in handler['prefix_calls']}
    remaining=[c for c in full['direct_calls'] if c['target_rva'] not in known]
    # Reviewed body roles are tied to original call order and repeated target
    # identity. No RVA or hash selects behavior in the production compiler.
    if len(remaining)!=6 or remaining[1]['target_rva']!=remaining[4]['target_rva']:
        raise ValueError('original handler dependency order or shared local wrapper changed')
    filter_bridge=dispatch_cfg(image,index,remaining[0]['target_rva'],'original-filter-bridge')
    local_wrapper=dispatch_cfg(image,index,remaining[1]['target_rva'],'original-local-unwind-wrapper')
    global_wrapper=dispatch_cfg(image,index,remaining[3]['target_rva'],'original-global-unwind-wrapper')
    selected=dispatch_cfg(image,index,remaining[5]['target_rva'],'original-selected-transfer')
    if len(local_wrapper['direct_calls'])!=1 or local_wrapper['return_sites'][-1]['pop_bytes']!=8:
        raise ValueError('original local wrapper call/cleanup ABI changed')
    local=dispatch_cfg(image,index,local_wrapper['direct_calls'][0]['target_rva'],'original-local-unwind')
    if len(local['direct_calls'])!=2:
        raise ValueError('original local unwind callback inventory changed')
    notification=dispatch_cfg(image,index,local['direct_calls'][0]['target_rva'],'original-notification')
    cleanup_bridge=dispatch_cfg(image,index,local['direct_calls'][1]['target_rva'],'original-cleanup-bridge')
    if len(selected['direct_calls'])!=1 or selected['direct_calls'][0]['target_rva']!=notification['rva']:
        raise ValueError('selected and cleanup paths use different notification effects')
    nested_values=[]
    for before,after in zip(local['instructions'],local['instructions'][1:]):
        raw=bytes.fromhex(before['code_hex'])
        if len(raw)==5 and raw[0]==0x68 and after['code_hex']=='64ff3500000000':nested_values.append(u32(raw,1))
    if len(nested_values)!=1:raise ValueError('temporary FS handler address is not uniquely bound')
    nested=dispatch_cfg(image,index,nested_values[0]-base,'original-nested-handler')
    if len(nested['direct_calls'])!=2 or nested['direct_calls'][1]['target_rva']!=local['rva']:
        raise ValueError('nested handler does not bind same original local-unwind loop')
    imported=global_wrapper['indirect_effects']
    if len(imported)!=1 or imported[0].get('import')!=['kernel32.dll','RtlUnwind']:
        raise ValueError('original global wrapper import is not RtlUnwind')
    call=index[imported[0]['rva']];resume=call['rva']+call['size']
    resume_arguments=[r for r in global_wrapper['instructions'] if r['code_hex']==(b'\x68'+struct.pack('<I',base+resume)).hex()]
    if len(resume_arguments)!=1 or resume not in {r['rva'] for r in global_wrapper['instructions']}:
        raise ValueError('original RtlUnwind TargetIp is not bound wrapper continuation')
    notification_bases=[u32(bytes.fromhex(r['code_hex']),1) for r in notification['instructions'] if r['size']==5 and r['code_hex'].startswith('bb')]
    if len(notification_bases)!=1:raise ValueError('notification module pointer is not unique')
    notification_base=notification_bases[0]
    stores=[r for r in notification['instructions'] if r['code_hex'] in ['894b08','894304','896b0c']]
    if [r['code_hex'] for r in stores]!=['894b08','894304','896b0c']:
        raise ValueError('notification stores/order changed')
    notification_words=[module_word(image,notification_base+offset,'NLG shared module word') for offset in [0,4,8,12]]
    if any(w['section_flags']&0x20000000 or not w['section_flags']&0x80000000 for w in notification_words):
        raise ValueError('notification record lacks writable nonexecutable module ownership')
    epilogs=[]
    for symbol in ['_Inner','_Outer','_main']:
        function=bound[symbol];rows=function_rows(function,index)
        positions=[i for i,r in enumerate(rows) if r['code_hex']=='64890d00000000']
        if len(positions)!=1 or positions[0]==0 or rows[positions[0]-1]['code_hex']!='8b4df0':
            raise ValueError('original normal FS teardown binding changed')
        epilogs.append(through_ret(function,rows,rows[positions[0]-1]['rva'],symbol[1:]+'-normal-epilog',
            'original normal-return epilog; not the exceptional cleanup path and not executed at current capture cut'))
    blocks=[full,local,nested,filter_bridge,selected,global_wrapper,local_wrapper,notification,cleanup_bridge]+epilogs
    metadata=dict(handler_rva=full['rva'],handler_direct_calls=full['direct_calls'],
        unresolved_cpp_helper=remaining[2],rtl_unwind_iat_rva=imported[0]['slot_rva'],
        rtl_unwind_call_rva=imported[0]['rva'],rtl_unwind_resume_rva=resume,
        nested_handler_rva=nested['rva'],nested_security_check_rva=nested['direct_calls'][0]['target_rva'],
        notification_record_rva=notification_base-base,notification_words=notification_words,
        notification_store_order=[dict(rva=r['rva'],code_hex=r['code_hex']) for r in stores],
        observed_runtime_fields='not measured here: callback flags, live FS chain, notification values and wrapper resume context',
        admission='inventory only; complete bytes are not proof of RtlUnwind, unknown callbacks or thread-state equivalence')
    return blocks,metadata


def frame_evidence(root):
    obj = (root/'unwind.obj').read_bytes()
    image = (root/'unwind.exe').read_bytes()
    symbols,sections = coff(obj)
    index = instructions((root/'disasm.txt').read_text(errors='strict'),image)
    bound = {name:bind_function(obj,image,name) for name in ['_Inner','_Outer','_main']}
    fragments = []
    frames = []
    for name in ['_Inner','_Outer','_main']:
        function = bound[name]
        rows = function_rows(function,index)
        table = bind_eh4(obj,image,function,symbols,sections)
        fs_stores = [r for r in rows if r['code_hex'] == '64a300000000']
        if len(fs_stores) != 1:
            raise ValueError('original registration store boundary is ambiguous')
        after_registration = fs_stores[0]['rva']+fs_stores[0]['size']
        prolog = fragment(function,rows,function['rva'],after_registration,name[1:]+'-prolog',
                          'original bytes retained; FS/handler/cookie effects require separate proof')
        fragments.append(prolog)
        calls = [r for r in rows if r['rva'] >= after_registration and
                 (r['code_hex'].startswith('e8') or r['code_hex'].startswith('ff15'))]
        if not calls:
            raise ValueError('missing original call boundary')
        first_call = calls[0]
        if name != '_main':
            initializer = fragment(function,rows,after_registration,first_call['rva'],name[1:]+'-initialize',
                'original contiguous initializer and argument setup; stops before effectful call')
            fragments.append(initializer)
            blocked = [call_binding(image,function,first_call)]
            if name == '_Inner':
                if blocked[0].get('import') != ['kernel32.dll','RaiseException']:
                    raise ValueError('original event call identity changed')
            elif blocked[0]['symbol'] != '_Inner' or blocked[0]['target_rva'] != bound['_Inner']['rva']:
                raise ValueError('original nested call identity changed')
        else:
            # Stop before the first outgoing argument push. Main's memset and
            # GetModuleHandle call gap remains explicit, not treated as no-op.
            prefix = [r for r in rows if after_registration <= r['rva'] < first_call['rva']]
            pushes = [r for r in prefix if r['code_hex'].startswith(('68','6a')) or r['code_hex'] in ['50','51','52','53','54','55','56','57']]
            if not pushes:
                raise ValueError('missing original main call argument boundary')
            initializer = fragment(function,rows,after_registration,pushes[0]['rva'],
                'main-initialize','isolated original stores; prior cookie/registration and subsequent external calls remain unproved')
            fragments.append(initializer)
            outer = [r for r in function['relocations'] if r['symbol'] == '_Outer' and r['kind'] == 0x14]
            if len(outer) != 1:
                raise ValueError('missing unique original Outer call')
            base,_ = pe_sections(image)
            if outer[0]['target_va'] != base+bound['_Outer']['rva']:
                raise ValueError('original Outer call target changed')
            outer_call = function['rva']+outer[0]['offset']-1
            scope_stores = [r for r in rows if initializer['rva']+initializer['size'] <= r['rva'] < outer_call and
                            len(bytes.fromhex(r['code_hex'])) == 7 and r['code_hex'].startswith('c745fc')]
            if len(scope_stores) != 1 or scope_stores[0]['rva']+7 != outer_call:
                raise ValueError('main scope activation cut is not the complete immediate predecessor')
            activation = fragment(function,rows,scope_stores[0]['rva'],outer_call,
                'main-activate','isolated scope store after an explicitly unproved external-effect gap')
            fragments.append(activation)
            gap_start = initializer['rva']+initializer['size']
            gap = fragment(function,rows,gap_start,activation['rva'],'main-unproved-gap',
                'NOT EXECUTED: outgoing arguments, memset, GetModuleHandleW, return values and output stores')
            fragments.append(gap)
            blocked = [call_binding(image,function,r)
                       for r in rows if gap_start <= r['rva'] < activation['rva'] and r in calls]
            if (len(blocked) != 2 or blocked[0]['symbol'] != '_memset'
                    or blocked[1].get('import') != ['kernel32.dll','GetModuleHandleW']):
                raise ValueError('main external effect gap changed')
        cleanup_fragments = []
        for entry in table['rows']:
            if entry['filter_rva'] is None:
                cleanup = through_ret(function,rows,entry['handler_rva'],
                    name[1:]+'-finally-'+str(entry['index']), 'complete original finally funclet including all output stores')
                fragments.append(cleanup)
                cleanup_fragments.append(cleanup['name'])
            else:
                filt = through_ret(function,rows,entry['filter_rva'],
                    name[1:]+'-filter-'+str(entry['index']), 'original code predicate and owned EXCEPTION_POINTERS reads')
                fragments.append(filt)
                # Handler continuation is not a RET function. The original
                # direct jump just before the filter identifies its join.
                predecessors = [r for r in rows if r['rva']+r['size'] == entry['filter_rva']]
                if len(predecessors) != 1 or not predecessors[0]['code_hex'].startswith('eb'):
                    raise ValueError('missing original handler continuation join')
                jump = predecessors[0]
                delta = struct.unpack('<b',bytes.fromhex(jump['code_hex'])[1:])[0]
                join = jump['rva']+jump['size']+delta
                handler = fragment(function,rows,entry['handler_rva'],join,
                    name[1:]+'-selected-handler-'+str(entry['index']),
                    'original saved-ESP load and handled/scope stores; stops at manual Restore setup')
                fragments.append(handler)
        frames.append(dict(symbol=name,rva=function['rva'],size=function['size'],sha256=function['sha256'],
                           table=table,initializer=initializer['name'],
                           initializer_stores=immediate_frame_stores(initializer['instructions']),
                           cleanup_fragments=cleanup_fragments,blocked_calls=blocked,
                           original_relocations=function['relocations']))
    handler_blocks,handler = handler_fragments(image,index,bound)
    fragments.extend(handler_blocks)
    observation=json.loads((root/'report.json').read_text())['observation']
    connected_blocks,connected=connected_helper_evidence(image,index,bound,frames,fragments,handler,observation)
    fragments.extend(connected_blocks)
    dispatch_blocks,dispatch=dispatch_evidence(image,index,bound,handler)
    fragments.extend(dispatch_blocks)
    return dict(kind='original frame/filter fragment provenance; not whole startup or Windows dispatch equivalence',
        pe_sha256=sha(image),object_sha256=sha(obj),disassembly_sha256=sha((root/'disasm.txt').read_bytes()),
        frames=frames,fragments=fragments,handler=handler,connected=connected,dispatch=dispatch,
        cuts=[
            'Original FS registration/cookie/handler state is retained but is not initialized by a slice extraction.',
            'Main initialization and activation are separate cuts; memset/GetModuleHandleW effects between them remain unproved.',
            'Original RaiseException delivery, native Windows frame selection and initial thread/module invariants remain outside fragment provenance.',
            'Finally funclets include output stores after Dispatch; trimming those effects would require a separate explicit boundary.',
            'Selected-handler ESP recovery is original code, not evidence that all original context fields are restored.'])


def write_evidence(root,out):
    report = frame_evidence(root)
    out.mkdir(parents=True,exist_ok=True)
    for block in report['fragments']+[f['table'] for f in report['frames']]:
        (out/block['file']).write_bytes(bytes.fromhex(block['code_hex']))
    (out/'frame-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def artifact_tests(root):
    """Independent fragment expectations and unexecuted evidence mutations."""
    import tempfile
    import unittest
    original = {name:(root/name).read_bytes() for name in ['unwind.obj','unwind.exe','disasm.txt','report.json']}
    baseline = frame_evidence(root)
    base,mappings = pe_sections(original['unwind.exe'])
    blocks = {b['name']:b for b in baseline['fragments']}
    def file_at(rva):
        matches = [s['start']+rva-s['rva'] for s in mappings if s['rva'] <= rva < s['rva']+min(s['virtual'],s['size'])]
        if len(matches) != 1:
            raise ValueError('test mutation needs unique original mapping')
        return matches[0]
    def replay(changes):
        with tempfile.TemporaryDirectory(prefix='w2l-frame-evidence-') as temp:
            directory = Path(temp)
            for name,raw in original.items():
                (directory/name).write_bytes(changes.get(name,raw))
            return frame_evidence(directory)
    def patch(raw,offset,replacement):
        return raw[:offset]+replacement+raw[offset+len(replacement):]
    class FrameEvidenceTests(unittest.TestCase):
        def test_original_initialization_is_instruction_derived(self):
            frames = {f['symbol']:f for f in baseline['frames']}
            self.assertEqual([(s['frame_offset'],s['value']) for s in frames['_Inner']['initializer_stores']],
                             [(-28,100),(-32,0),(-4,0),(-4,1)])
            self.assertEqual([(s['frame_offset'],s['value']) for s in frames['_Outer']['initializer_stores']],
                             [(-28,200),(-32,2),(-4,0)])
            self.assertEqual([(s['frame_offset'],s['value']) for s in frames['_main']['initializer_stores']],
                             [(-768,300),(-752,0)])
        def test_effectful_main_gap_is_retained(self):
            gap = blocks['main-unproved-gap']
            calls = [r for r in gap['instructions'] if r['code_hex'].startswith(('e8','ff15'))]
            self.assertEqual(len(calls),2)
            self.assertLess(blocks['main-initialize']['rva'],gap['rva'])
            self.assertEqual(gap['rva']+gap['size'],blocks['main-activate']['rva'])
            self.assertNotIn(-4,[s['frame_offset'] for s in baseline['frames'][2]['initializer_stores']])
        def test_complete_cleanup_and_normalizer_effects(self):
            for name in ['Inner-finally-0','Outer-finally-0']:
                self.assertEqual(sum(r['code_hex'].startswith('a3') for r in blocks[name]['instructions']),2)
                self.assertEqual(blocks[name]['instructions'][-1]['code_hex'],'c3')
            normalizer = blocks['event-normalizer']['instructions']
            self.assertTrue(any(r['code_hex'].startswith('0fae') for r in normalizer))
            self.assertEqual(sum(r['code_hex'] == 'c3' for r in normalizer),5)
            self.assertEqual(blocks['main-filter-0']['instructions'][-1]['code_hex'],'c3')
        def test_complete_dispatch_retains_unresolved_effects(self):
            dispatch=baseline['dispatch']
            self.assertEqual(blocks['original-handler-complete']['size'],350)
            self.assertEqual(blocks['original-local-unwind']['size'],159)
            self.assertEqual(blocks['original-nested-handler']['size'],70)
            self.assertEqual(dispatch['rtl_unwind_resume_rva'],dispatch['rtl_unwind_call_rva']+6)
            self.assertEqual([r['code_hex'] for r in dispatch['notification_store_order']],
                             ['894b08','894304','896b0c'])
            self.assertIn('not measured',dispatch['observed_runtime_fields'])
            self.assertTrue(dispatch['unresolved_cpp_helper'])
        def test_changed_runtime_import_cannot_reuse_dispatch_binding(self):
            image=original['unwind.exe']
            self.assertEqual(image.count(b'RtlUnwind\0'),1)
            changed=image.replace(b'RtlUnwind\0',b'RtlUnwina\0')
            with self.assertRaisesRegex(ValueError,'not RtlUnwind'):
                replay({'unwind.exe':changed})
        def test_disassembly_is_not_an_unchecked_oracle(self):
            text = original['disasm.txt'].decode()
            needle = '004010C0: 55'
            self.assertIn(needle,text)
            changed = text.replace(needle,'004010C0: 54',1).encode()
            with self.assertRaises(ValueError): replay({'disasm.txt':changed})
        def test_eh4_handler_target_must_bind_original_local_symbol(self):
            table = baseline['frames'][0]['table']
            offset = file_at(table['rva'])+24
            changed = patch(original['unwind.exe'],offset,struct.pack('<I',base+table['rows'][1]['handler_rva']))
            with self.assertRaises(ValueError): replay({'unwind.exe':changed})
        def test_self_parent_rejects_even_with_matching_object_bytes(self):
            table = baseline['frames'][0]['table']
            symbols,sections = coff(original['unwind.obj'])
            symbol = next(s for s in symbols.values() if s['name'] == table['symbol'])
            section = sections[symbol['section']-1]
            obj = patch(original['unwind.obj'],section['start']+16,struct.pack('<i',0))
            image = patch(original['unwind.exe'],file_at(table['rva'])+16,struct.pack('<i',0))
            with self.assertRaises(ValueError): replay({'unwind.obj':obj,'unwind.exe':image})
        def test_fragment_boundary_requires_original_instruction(self):
            function = bind_function(original['unwind.obj'],original['unwind.exe'],'_Inner')
            index = instructions(original['disasm.txt'].decode(),original['unwind.exe'])
            rows = function_rows(function,index)
            start = blocks['Inner-initialize']['rva']+1
            with self.assertRaises(ValueError): fragment(function,rows,start,start+6,'bad','test')
        def test_connected_helpers_retain_failure_and_initial_state_limits(self):
            self.assertTrue(blocks['original-guard-validator']['direct_calls'])
            self.assertTrue(blocks['original-guard-validator']['external_tail_edges'])
            self.assertEqual(blocks['original-security-check']['external_tail_edges'][0]['target_rva'],
                             baseline['connected']['security_failure_target_rva'])
            self.assertEqual(len(blocks['original-context-check']['traps']),1)
            memset=blocks['original-memset']['instructions']
            self.assertTrue(any(row['code_hex']=='f3aa' for row in memset))
            self.assertTrue(any(row['code_hex'].startswith('f30f7f') for row in memset))
            words=baseline['connected']['memset_feature_words']
            self.assertEqual(sorted((w['file_backed_bytes'],w['zero_fill_bytes']) for w in words),[(0,4),(4,0)])
        def test_cookie_comparison_must_match_prolog_identity(self):
            check=blocks['original-security-check']
            row=check['instructions'][0];raw=bytes.fromhex(row['code_hex'])
            changed=raw[:2]+struct.pack('<I',u32(raw,2)+4)
            image=patch(original['unwind.exe'],file_at(row['rva']),changed)
            text=original['disasm.txt'].decode()
            address=f'{base+row["rva"]:08X}:'
            lines=text.splitlines(keepends=True)
            found=[i for i,line in enumerate(lines) if address in line]
            self.assertEqual(len(found),1)
            before=' '.join(f'{b:02X}' for b in raw)
            after=' '.join(f'{b:02X}' for b in changed)
            self.assertIn(before,lines[found[0]])
            lines[found[0]]=lines[found[0]].replace(before,after,1)
            with self.assertRaisesRegex(ValueError,'cookie provenance'):
                replay({'unwind.exe':image,'disasm.txt':''.join(lines).encode()})
        def test_continuation_includes_real_restore_call_and_capture(self):
            continuation=blocks['selected-through-capture']
            self.assertEqual([r['register'] for r in continuation['capture_stores']],['EAX','ESP','EBP'])
            self.assertTrue(any(r['rva']==continuation['restore_call_rva'] and r['code_hex'].startswith('e8')
                                for r in continuation['instructions']))
            self.assertTrue(any(r['code_hex'].startswith('830d') for r in continuation['instructions']))
            report=json.loads(original['report.json'])
            report['observation']['restore_target_rva']+=6
            with self.assertRaisesRegex(ValueError,'capture sequence'):
                replay({'report.json':json.dumps(report).encode()})
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FrameEvidenceTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--test-artifact':
        artifact_tests(Path(sys.argv[2]).resolve())
    else:
        report = write_evidence(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
        print(json.dumps(report,indent=2))
