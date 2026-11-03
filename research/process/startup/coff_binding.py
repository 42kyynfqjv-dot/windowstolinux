"""Bounded original COFF-to-PE provenance; never a converter eligibility rule.

Only ordinary x86 COFF, one function per executable COMDAT section and four-byte
DIR32/REL32 relocation sites are admitted. Symbols identify research evidence,
not application dispatch in production. Unknown formats or ambiguous matches fail.
"""
import hashlib
import struct
from inventory import mapped_bytes


def cut(data, offset, size):
    if not 0 <= offset <= len(data) or not 0 <= size <= len(data)-offset:
        raise ValueError('truncated evidence range')
    return data[offset:offset+size]


def u32(data, at):
    return struct.unpack('<I', cut(data, at, 4))[0]


def coff(data):
    machine, count, _, symbols_at, symbol_count, optional_size, _ = struct.unpack('<HHIIIHH', cut(data, 0, 20))
    if machine != 0x14c or not 1 <= count <= 256 or optional_size or not 1 <= symbol_count <= 65536:
        raise ValueError('unsupported ordinary x86 COFF header')
    symbol_bytes = cut(data, symbols_at, symbol_count*18)
    strings_at = symbols_at+symbol_count*18
    strings_size = u32(data, strings_at)
    if not 4 <= strings_size <= 1024*1024:
        raise ValueError('invalid bounded COFF string table')
    strings = cut(data, strings_at, strings_size)
    symbols = {}
    index = 0
    while index < symbol_count:
        raw = symbol_bytes[index*18:(index+1)*18]
        if raw[:4] == b'\0'*4:
            offset = u32(raw, 4)
            if not 4 <= offset < len(strings):
                raise ValueError('COFF symbol name outside string table')
            end = strings.find(b'\0', offset)
            if end == -1:
                raise ValueError('unterminated COFF symbol name')
            name = strings[offset:end]
        else:
            name = raw[:8].split(b'\0', 1)[0]
        value, section, kind, storage, aux = struct.unpack('<IhHBB', raw[8:])
        if index+aux >= symbol_count:
            raise ValueError('COFF auxiliary records outside symbol table')
        symbols[index] = dict(name=name.decode('ascii'), value=value, section=section,
                              kind=kind, storage=storage)
        index += 1+aux
    sections = []
    for index in range(count):
        raw = cut(data, 20+index*40, 40)
        size, start, reloc_at = struct.unpack_from('<III', raw, 16)
        reloc_count = struct.unpack_from('<H', raw, 32)[0]
        flags = u32(raw, 36)
        if size > 1024*1024 or reloc_count > 4096 or flags & 0x01000000:
            raise ValueError('COFF section resource limit or extended relocations')
        relocs = []
        for at in range(reloc_count):
            offset, symbol, kind = struct.unpack('<IIH', cut(data, reloc_at+at*10, 10))
            if symbol not in symbols:
                raise ValueError('relocation uses missing/auxiliary COFF symbol')
            relocs.append(dict(offset=offset, symbol=symbols[symbol]['name'], kind=kind))
        sections.append(dict(size=size, start=start, flags=flags, relocs=relocs))
    return symbols, sections


def pe_sections(data):
    at = u32(data, 60)
    if cut(data, at, 4) != b'PE\0\0':
        raise ValueError('missing PE signature')
    machine, count = struct.unpack('<HH', cut(data, at+4, 4))
    optional = struct.unpack('<H', cut(data, at+20, 2))[0]
    if machine != 0x14c or not 1 <= count <= 256 or optional < 96 or struct.unpack('<H', cut(data, at+24, 2))[0] != 0x10b:
        raise ValueError('unsupported PE32 evidence')
    base = u32(data, at+52)
    sections = []
    for index in range(count):
        raw = cut(data, at+24+optional+index*40, 40)
        virtual, rva, size, start = struct.unpack_from('<IIII', raw, 8)
        flags = u32(raw, 36)
        if rva+virtual > 2**32 or base+rva+virtual > 2**32:
            raise ValueError('PE virtual range overflow')
        sections.append(dict(rva=rva, virtual=virtual, size=size, start=start, flags=flags))
    return base, sections


def bind_function(obj, image, name):
    symbols, sections = coff(obj)
    found = [s for s in symbols.values() if s['name'] == name and s['kind'] == 0x20]
    if len(found) != 1:
        raise ValueError('missing/ambiguous COFF function symbol')
    symbol = found[0]
    if not 1 <= symbol['section'] <= len(sections) or symbol['value'] != 0:
        raise ValueError('function must begin its own COFF section')
    section = sections[symbol['section']-1]
    if not section['flags'] & 0x20000000 or not section['flags'] & 0x1000 or not 1 <= section['size'] <= 65536:
        raise ValueError('function needs bounded executable COMDAT section')
    if sum(s['section'] == symbol['section'] and s['kind'] == 0x20 for s in symbols.values()) != 1:
        raise ValueError('multiple functions in COFF section')
    code = cut(obj, section['start'], section['size'])
    mask = bytearray(b'\1'*len(code))
    for relocation in section['relocs']:
        offset = relocation['offset']
        if relocation['kind'] not in (0x6, 0x14) or offset+4 > len(code) or mask[offset:offset+4] != b'\1'*4:
            raise ValueError('unsupported/outside/overlapping COFF relocation')
        mask[offset:offset+4] = b'\0'*4
    runs = []
    start = 0
    while start < len(mask):
        if not mask[start]:
            start += 1
            continue
        end = start+1
        while end < len(mask) and mask[end]:
            end += 1
        runs.append((start, end))
        start = end
    anchor_start, anchor_end = max(runs, key=lambda pair: pair[1]-pair[0], default=(0, 0))
    if anchor_end-anchor_start < 8:
        raise ValueError('insufficient original instruction identity')
    anchor = code[anchor_start:anchor_end]
    base, mapped = pe_sections(image)
    matches = []
    for mapping in mapped:
        if not mapping['flags'] & 0x20000000:
            continue
        size = min(mapping['size'], mapping['virtual'])
        if size > 16*1024*1024:
            raise ValueError('executable evidence range exceeds matching budget')
        body = cut(image, mapping['start'], size)
        position = body.find(anchor)
        while position != -1:
            begin = position-anchor_start
            candidate = body[begin:begin+len(code)] if begin >= 0 else b''
            if len(candidate) == len(code) and all(not mask[i] or code[i] == candidate[i] for i in range(len(code))):
                matches.append((mapping['rva']+begin, candidate))
            position = body.find(anchor, position+1)
    if len(matches) != 1:
        raise ValueError('original COFF function not uniquely bound to executable PE bytes')
    rva, linked = matches[0]
    bindings = []
    for relocation in section['relocs']:
        offset = relocation['offset']
        addend = u32(code, offset)
        linked_word = u32(linked, offset)
        if relocation['kind'] == 0x6:
            target = (linked_word-addend) & 0xffffffff
        else:
            # COFF REL32 relocation adds S-(P+4) to the encoded addend.
            target = (linked_word+base+rva+offset+4-addend) & 0xffffffff
        bindings.append(dict(**relocation, addend=addend, linked_word=linked_word, target_va=target))
    return dict(symbol=name, rva=rva, size=len(linked), code_hex=linked.hex(),
                sha256=hashlib.sha256(linked).hexdigest(), relocations=bindings,
                object_section=symbol['section'], object_section_sha256=hashlib.sha256(code).hexdigest())


def dispatcher_evidence(obj, image, table_rva):
    """Bind the authored Dispatch and direct callers; no Windows SEH selection claim."""
    base, sections = pe_sections(image)
    dispatch = bind_function(obj, image, '_Dispatch')
    bindings = dispatch['relocations']
    if len(bindings) != 5 or any(b['kind'] != 6 for b in bindings):
        raise ValueError('unexpected authored dispatcher relocation dependencies')
    traces = [b for b in bindings if b['symbol'] == '_trace_value']
    tables = [b for b in bindings if b['symbol'] == '_ScopeTable']
    exits = [b for b in bindings if b['symbol'] == '__imp__ExitProcess@4']
    if len(traces) != 2 or len(tables) != 2 or len(exits) != 1:
        raise ValueError('dispatcher external effect inventory changed')
    if any(b['addend'] != 0 for b in traces+exits) or traces[0]['target_va'] != traces[1]['target_va']:
        raise ValueError('dispatcher trace/exit relocation mismatch')
    exit_iat_rva = exits[0]['target_va']-base
    if import_at_iat(image, exit_iat_rva) != ('kernel32.dll', 'ExitProcess'):
        raise ValueError('dispatcher failure import is not bound to original kernel32 ExitProcess')
    if sorted(b['addend'] for b in tables) != [0, 4] or any(b['target_va'] != base+table_rva for b in tables):
        raise ValueError('dispatcher scope-table loads not bound to original observed table')
    trace = traces[0]['target_va']
    mappings = [s for s in sections if base+s['rva'] <= trace and trace+4 <= base+s['rva']+s['virtual']]
    if len(mappings) != 1 or mappings[0]['flags'] & 0x20000000 or not mappings[0]['flags'] & 0x80000000:
        raise ValueError('trace is not a unique writable non-code image word')
    callers = []
    for name, count in [('_Inner', 2), ('_Outer', 1)]:
        caller = bind_function(obj, image, name)
        calls = [b for b in caller['relocations'] if b['symbol'] == '_Dispatch']
        if len(calls) != count or any(b['kind'] != 0x14 or b['addend'] != 0 or b['target_va'] != base+dispatch['rva'] for b in calls):
            raise ValueError('original caller not bound to dispatcher')
        linked = bytes.fromhex(caller['code_hex'])
        if any(b['offset'] == 0 or linked[b['offset']-1] != 0xe8 for b in calls):
            raise ValueError('dispatcher reference is not an original direct CALL')
        callers.append(dict(symbol=name, rva=caller['rva'],size=caller['size'],sha256=caller['sha256'],
                            call_rvas=[caller['rva']+b['offset']-1 for b in calls]))
    dispatch.update(trace_rva=trace-base, table_rva=table_rva,
                    table_target_load_offset=next(b['offset'] for b in tables if b['addend'] == 4),
                    table_parent_load_offset=next(b['offset'] for b in tables if b['addend'] == 0),
                    exit_iat_rva=exit_iat_rva,
                    callers=callers, object_sha256=hashlib.sha256(obj).hexdigest(),
                    file='Dispatch.bin',
                    limits='COFF symbol/relocation and original-call provenance only; active frame/SEH selection remains unproved')
    return dispatch


def import_at_iat(image, wanted_rva):
    """Bind the original failure call's IAT slot, including its loader name."""
    base, _ = pe_sections(image)
    header = u32(image, 60)
    optional_size = struct.unpack('<H', cut(image, header+20, 2))[0]
    if optional_size < 112 or u32(image, header+24+92) < 2:
        raise ValueError('missing import directory')
    directory_rva, directory_size = struct.unpack('<II', cut(image, header+24+104, 8))
    if not directory_rva or not 20 <= directory_size <= 64*20:
        raise ValueError('import descriptor evidence budget')
    def read(rva, size):
        return mapped_bytes(image, base+rva, size)
    def cstring(rva):
        result = bytearray()
        for offset in range(256):
            byte = read(rva+offset,1)
            if byte == b'\0':
                return result.decode('ascii')
            result.extend(byte)
        raise ValueError('unterminated import name')
    matches = []
    terminated = False
    for index in range(directory_size//20):
        words = struct.unpack('<IIIII',read(directory_rva+index*20,20))
        if words == (0,0,0,0,0):
            terminated = True
            break
        original, _, _, name_rva, iat = words
        if not original or not name_rva or not iat:
            raise ValueError('unsupported import descriptor')
        library = cstring(name_rva).lower()
        for entry in range(4096):
            thunk = struct.unpack('<I',read(original+entry*4,4))[0]
            if not thunk:
                break
            if iat+entry*4 == wanted_rva:
                if thunk & 0x80000000:
                    raise ValueError('ordinal failure import unsupported')
                matches.append((library,cstring(thunk+2)))
        else:
            raise ValueError('import thunk evidence budget')
    if not terminated or len(matches) != 1:
        raise ValueError('missing or ambiguous failure import binding')
    return matches[0]


def artifact_tests(root):
    """Mutate retained authored evidence in memory; never execute modified PEs."""
    import unittest
    obj = (root/'unwind.obj').read_bytes()
    image = (root/'unwind.exe').read_bytes()
    import json
    table_rva = json.loads((root/'report.json').read_text())['table_rva']
    baseline = dispatcher_evidence(obj,image,table_rva)
    symbols, sections = coff(obj)
    section = sections[baseline['object_section']-1]
    _, mappings = pe_sections(image)
    code_mapping = next(s for s in mappings if s['rva'] <= baseline['rva'] < s['rva']+s['virtual'])
    raw_dispatch = code_mapping['start']+baseline['rva']-code_mapping['rva']
    reloc_at = u32(obj,20+(baseline['object_section']-1)*40+24)
    def patched(data,at,replacement):
        return data[:at]+replacement+data[at+len(replacement):]
    class BindingTests(unittest.TestCase):
        def test_exact_original_binding(self):
            self.assertEqual(bytes.fromhex(baseline['code_hex']),cut(image,raw_dispatch,baseline['size']))
            self.assertEqual([len(c['call_rvas']) for c in baseline['callers']],[2,1])
        def test_nonrelocated_instruction_identity(self):
            changed = patched(obj,section['start'],bytes([obj[section['start']]^0x80]))
            with self.assertRaises(ValueError): dispatcher_evidence(changed,image,table_rva)
            changed = patched(image,raw_dispatch,bytes([image[raw_dispatch]^0x80]))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
        def test_truncation_and_auxiliary_symbol(self):
            for size in (19,u32(obj,8)+u32(obj,12)*18+3,len(obj)-1):
                with self.assertRaises(ValueError): dispatcher_evidence(obj[:size],image,table_rva)
            auxiliary_index = next(i for i in range(u32(obj,12)) if i not in symbols)
            changed = patched(obj,reloc_at+4,struct.pack('<I',auxiliary_index))
            with self.assertRaises(ValueError): dispatcher_evidence(changed,image,table_rva)
        def test_relocation_type_and_overlap(self):
            changed = patched(obj,reloc_at+8,struct.pack('<H',0xffff))
            with self.assertRaises(ValueError): dispatcher_evidence(changed,image,table_rva)
            changed = patched(obj,reloc_at+10,cut(obj,reloc_at,4))
            with self.assertRaises(ValueError): dispatcher_evidence(changed,image,table_rva)
        def test_ambiguous_original_function(self):
            # A second identical executable candidate must not be picked by order.
            other = code_mapping['start']+min(code_mapping['size'],code_mapping['virtual'])-baseline['size']
            self.assertNotEqual(other,raw_dispatch)
            changed = patched(image,other,bytes.fromhex(baseline['code_hex']))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
        def test_scope_and_trace_target_identity(self):
            offset = baseline['table_target_load_offset']
            changed = patched(image,raw_dispatch+offset,struct.pack('<I',u32(image,raw_dispatch+offset)+8))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
            changed = image
            base,_ = pe_sections(image)
            for binding in baseline['relocations']:
                if binding['symbol'] == '_trace_value':
                    changed = patched(changed,raw_dispatch+binding['offset'],struct.pack('<I',base+baseline['rva']))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
        def test_original_direct_caller_binding(self):
            call_rva = baseline['callers'][0]['call_rvas'][0]
            offset = code_mapping['start']+call_rva-code_mapping['rva']+1
            changed = patched(image,offset,struct.pack('<I',(u32(image,offset)+1)&0xffffffff))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
        def test_failure_api_identity_not_just_coff_name(self):
            binding = next(b for b in baseline['relocations'] if b['symbol'] == '__imp__ExitProcess@4')
            offset = raw_dispatch+binding['offset']
            changed = patched(image,offset,struct.pack('<I',u32(image,offset)+4))
            with self.assertRaises(ValueError): dispatcher_evidence(obj,changed,table_rva)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BindingTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == '__main__':
    import sys
    from pathlib import Path
    if len(sys.argv) != 3 or sys.argv[1] != '--test-artifact':
        raise SystemExit('coff_binding.py --test-artifact ORIGINAL_UNWIND_DIRECTORY')
    artifact_tests(Path(sys.argv[2]).resolve())
