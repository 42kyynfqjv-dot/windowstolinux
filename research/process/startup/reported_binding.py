"""Original Main completion provenance; never a CRT/whole-PE certificate."""
import hashlib
import json
from pathlib import Path
import re
import struct

from coff_binding import bind_function,coff,cut,u32,pe_sections
from frame_binding import frame_evidence,instructions,function_rows,fragment,dispatch_cfg,module_word
from inventory import mapped_bytes


def sha(raw):return hashlib.sha256(raw).hexdigest()


def original_leaf(obj,image,symbol,address):
    """Bind a small address-bearing leaf by its original caller relocation.

    Short leaves lack enough bytes for unique whole-image search. Their entry
    identity comes from the unique original caller edge, with every unrelocated
    byte and every four-byte object relocation independently checked below.
    """
    symbols,sections=coff(obj)
    found=[s for s in symbols.values() if s['name']==symbol]
    if len(found)!=1 or not 1<=found[0]['section']<=len(sections):raise ValueError('original leaf symbol missing')
    sym=found[0];section=sections[sym['section']-1]
    if sym['value']!=0 or not section['flags']&0x20000000 or not 1<=section['size']<=64:
        raise ValueError('unsupported original leaf extent')
    raw=cut(obj,section['start'],section['size']);linked=mapped_bytes(image,address,len(raw));mask=bytearray(b'\1'*len(raw));bindings=[]
    for reloc in section['relocs']:
        offset=reloc['offset']
        if reloc['kind']!=6 or offset+4>len(raw) or mask[offset:offset+4]!=b'\1'*4:
            raise ValueError('unsupported original leaf relocation')
        target=u32(linked,offset)
        bindings.append(dict(offset=offset,symbol=reloc['symbol'],target_va=target,addend=u32(raw,offset)))
        mask[offset:offset+4]=b'\0'*4
    if any(mask[i] and raw[i]!=linked[i] for i in range(len(raw))):raise ValueError('original leaf changed outside relocations')
    return linked,bindings


def extract(original,out):
    obj=(original/'unwind.obj').read_bytes();image=(original/'unwind.exe').read_bytes()
    base,_=pe_sections(image);index=instructions((original/'disasm.txt').read_text(),image)
    prior=frame_evidence(original);blocks={b['name']:b for b in prior['fragments']}
    main=bind_function(obj,image,'_main');wrapper=bind_function(obj,image,'_printf')
    rows=function_rows(main,index);start=blocks['selected-through-capture']['capture_end_rva']
    end=main['rva']+main['size']
    if index[end-1]['code_hex']!='c3':raise ValueError('Main completion does not end at original RET')
    completion=fragment(main,rows,start,end,'main-completion','actual post-capture formatting, return selection, FS restoration, guard and RET')
    printf_calls=[r for r in main['relocations'] if r['symbol']=='_printf' and r['kind']==0x14]
    if len(printf_calls)!=1 or printf_calls[0]['target_va']!=base+wrapper['rva']:
        raise ValueError('Main printf edge not bound to original COFF function')
    calls={}
    for name in ['___acrt_iob_func','___local_stdio_printf_options','___stdio_common_vfprintf']:
        found=[r for r in wrapper['relocations'] if r['symbol']==name and r['kind']==0x14 and r['addend']==0]
        if len(found)!=1:raise ValueError('original printf helper edge missing: '+name)
        calls[name]=found[0]['target_va']
    options,option_relocs=original_leaf(obj,image,'___local_stdio_printf_options',calls['___local_stdio_printf_options'])
    if len(options)!=6 or options[0]!=0xb8 or options[-1]!=0xc3 or len(option_relocs)!=1 or option_relocs[0]['offset']!=1:
        raise ValueError('original options accessor is not the bound address leaf')
    options_va=u32(options,1)
    iob=dispatch_cfg(image,index,calls['___acrt_iob_func']-base,'iob-helper')
    iob_bytes=bytes.fromhex(iob['code_hex'])
    # This evidence checker bounds the actual observed accessor. Production
    # compilers independently prove its operand effects rather than trust it.
    if len(iob_bytes)!=16 or iob_bytes[:9]!=bytes.fromhex('8bff558bec6b450838') or iob_bytes[9]!=0x05 or iob_bytes[-2:]!=b'\x5d\xc3':
        raise ValueError('original iob accessor layout changed')
    iob_base=u32(iob_bytes,10)
    call_rva=main['rva']+printf_calls[0]['offset']-1
    preceding=[r for r in rows if r['rva']+r['size']==call_rva]
    if len(preceding)!=1 or preceding[0]['size']!=5 or not preceding[0]['code_hex'].startswith('68'):
        raise ValueError('printf format is not original immediate argument')
    format_va=u32(bytes.fromhex(preceding[0]['code_hex']),1)
    refs=[r for r in main['relocations'] if r['offset']==preceding[0]['rva']-main['rva']+1 and r['kind']==6]
    if len(refs)!=1 or refs[0]['target_va']!=format_va:raise ValueError('format lacks original object relocation')
    symbols,sections=coff(obj);symbol=[s for s in symbols.values() if s['name']==refs[0]['symbol']]
    if len(symbol)!=1 or not 1<=symbol[0]['section']<=len(sections):raise ValueError('format object symbol missing')
    section=sections[symbol[0]['section']-1];raw=cut(obj,section['start']+symbol[0]['value'],section['size']-symbol[0]['value'])
    if section['relocs'] or len(raw)>4096 or not raw.endswith(b'\0') or b'\0' in raw[:-1]:raise ValueError('format is not complete bounded object string')
    if mapped_bytes(image,format_va,len(raw))!=raw:raise ValueError('original format object/PE mismatch')
    directives=re.findall(rb'%(?:lu|ld|d)',raw[:-1])
    if re.sub(rb'%(?:lu|ld|d)',b'',raw[:-1]).find(b'%')!=-1 or [directives.count(x) for x in [b'%lu',b'%ld',b'%d']]!=[13,2,2]:
        raise ValueError('frozen original format directives changed')
    read_addresses=set()
    for row in completion['instructions']:
        code=bytes.fromhex(row['code_hex'])
        if code[:1]==b'\xa1' and len(code)==5:read_addresses.add(u32(code,1))
        elif code[:2] in [b'\x8b\x0d',b'\x8b\x15',b'\x81\x3d',b'\x83\x3d'] and len(code)>=6:read_addresses.add(u32(code,2))
    regions=[('main-completion',base+start,bytes.fromhex(completion['code_hex'])),
             ('printf-wrapper',base+wrapper['rva'],mapped_bytes(image,base+wrapper['rva'],wrapper['size'])),
             ('iob-helper',calls['___acrt_iob_func'],iob_bytes),
             ('stdio-options-helper',calls['___local_stdio_printf_options'],options),
             ('printf-format',format_va,raw)]
    files=[]
    for name,va,data in regions:
        filename=name+'.bin';(out/filename).write_bytes(data)
        files.append(dict(name=name,va=va,rva=va-base,size=len(data),sha256=sha(data),file=filename))
    formatter=calls['___stdio_common_vfprintf']
    if formatter-base not in index:raise ValueError('formatter target not original instruction boundary')
    result=dict(regions=files,printf_call_rva=call_rva,formatter_va=formatter,
        formatter_boundary='Original linked function entry from COFF relocation; formatter body is NOT lifted by this evidence binding.',
        format_hex=raw.hex(),directives=[d.decode() for d in directives],
        argument_words=17,stack_words_including_format=18,
        options_va=options_va,options_words=[module_word(image,options_va+i,'printf options word; runtime initialization unproved') for i in [0,4]],
        iob_base=iob_base,iob_stride=56,iob_index=1,stdout_address=iob_base+56,
        scalar_reads=[module_word(image,va,'Main completion scalar read') for va in sorted(read_addresses)],
        provenance='Caller COFF relocation + exact original instruction/data bytes; not function-name production dispatch',
        flush_boundary='Successful deferred text-mode flush is a separately supplied effect contract, not proved CRT startup or process exit')
    (out/'reported-binding.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
