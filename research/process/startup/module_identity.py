"""Metadata only: no copied handler implementation or executable loading."""
import ctypes
import hashlib
from pathlib import Path
import struct

def identify(data, handler_rva, machine, timestamp, image_size):
    def read(at,n):
        if at<0 or n<0 or at+n>len(data): raise ValueError('truncated module metadata')
        return data[at:at+n]
    def u16(at): return struct.unpack('<H',read(at,2))[0]
    def u32(at): return struct.unpack('<I',read(at,4))[0]
    pe=u32(60);optional=pe+24
    if (read(0,2)!=b'MZ' or read(pe,4)!=b'PE\0\0' or u16(optional)!=0x10b or
        u16(pe+4)!=machine or u32(pe+8)!=timestamp or u32(optional+56)!=image_size):
        raise ValueError('disk module does not match observed x86 headers')
    count=u16(pe+6);sections=optional+u16(pe+20)
    if count>96: raise ValueError('section budget')
    def mapped(rva,n):
        hits=[]
        for i in range(count):
            at=sections+40*i;virtual,va,raw_size,raw=struct.unpack('<IIII',read(at+8,16))
            if va<=rva and rva+n<=va+min(virtual,raw_size): hits.append(raw+rva-va)
        if len(hits)!=1: raise ValueError('ambiguous/unbacked module metadata')
        return read(hits[0],n)
    def word(rva): return struct.unpack('<I',mapped(rva,4))[0]
    def name(rva):
        value=bytearray()
        for i in range(512):
            b=mapped(rva+i,1)[0]
            if b==0:return value.decode('ascii')
            value.append(b)
        raise ValueError('export name budget')
    exports=[]
    if u32(optional+92)>0:
        directory,size=struct.unpack('<II',read(optional+96,8))
        if directory:
            raw=mapped(directory,40)
            functions,names,addresses,names_at,ordinals=struct.unpack_from('<IIIII',raw,20)
            if functions>65536 or names>65536: raise ValueError('export budget')
            for i in range(names):
                ordinal=struct.unpack('<H',mapped(ordinals+2*i,2))[0]
                if ordinal>=functions: raise ValueError('export ordinal')
                address=word(addresses+4*ordinal)
                if address==handler_rva and not directory<=address<directory+size:
                    exports.append(name(word(names_at+4*i)))
    return dict(sha256=hashlib.sha256(data).hexdigest(),machine=machine,
                timestamp=timestamp,image_size=image_size,handler_rva=handler_rva,
                exact_named_exports=exports,
                symbol_status='exact export' if exports else 'no exact named export; private symbol unresolved')

def version(path):
    api=ctypes.WinDLL('version',use_last_error=True)
    api.GetFileVersionInfoSizeW.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_uint32)]
    api.GetFileVersionInfoSizeW.restype=ctypes.c_uint32
    n=api.GetFileVersionInfoSizeW(str(path),None)
    if not n or n>1024*1024: raise ValueError('version metadata unavailable')
    buf=ctypes.create_string_buffer(n)
    api.GetFileVersionInfoW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
    api.VerQueryValueW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint32)]
    ptr=ctypes.c_void_p();size=ctypes.c_uint32()
    if not api.GetFileVersionInfoW(str(path),0,n,buf) or not api.VerQueryValueW(buf,'\\',ctypes.byref(ptr),ctypes.byref(size)) or size.value<52:
        raise ValueError('fixed version metadata unavailable')
    words=struct.unpack('<13I',ctypes.string_at(ptr,52))
    if words[0]!=0xfeef04bd: raise ValueError('version signature')
    return '.'.join(str(x) for x in (words[2]>>16,words[2]&65535,words[3]>>16,words[3]&65535))

def observed_module(report):
    # GetFinalPathNameByHandle uses the actual mapped file handle, avoiding a
    # guessed System32 path and architecture redirection when Python is 64-bit.
    path=Path(bytes.fromhex(report['module_path_hex']).decode('ascii'))
    result=identify(path.read_bytes(),report['handler']-report['handler_allocation'],
                    report['module_machine'],report['module_timestamp'],report['module_size'])
    result.update(file_name=path.name,resolved_file=str(path),file_version=version(path))
    return result
