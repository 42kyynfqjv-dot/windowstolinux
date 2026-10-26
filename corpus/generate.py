"""SUB-513 v2 authored PE generator. No production/older fixture imports."""
import struct
VERSION = 2
SEED = 513

class Code:
    def __init__(self): self.b=bytearray(); self.labels={}; self.fix=[]
    def raw(self,b): self.b.extend(b)
    def imm(self,op,n): self.raw(bytes([op])+struct.pack('<I',n))
    def label(self,name): self.labels[name]=len(self.b)
    def edge(self,op,label,width):
        self.raw(bytes([op]));self.fix.append((len(self.b),label,width));self.raw(bytes(width))
    def finish(self):
        for at,label,width in self.fix:
            self.b[at:at+width]=(self.labels[label]-at-width).to_bytes(width,'little',signed=True)
        return self.b

def build(index):
    family, variant=divmod(index,8)
    payload=(f'C{index:02d}'.encode() if variant not in (0,7) else b'!' if variant==0 else b'Z'*64)
    buffer_offset=255 if index==0 else variant
    shift=variant*4
    ilt,iat,dll,name=0x3040+shift,0x3080+shift,0x30b0,0x30c0
    c=Code()
    def output():
        c.imm(0x68,len(payload));c.imm(0x68,0x402000+buffer_offset);c.imm(0x68,1)
        c.raw(b'\xff\x15'+struct.pack('<I',0x400000+iat))
        c.raw(bytes.fromhex('8d642404')*3)
        c.imm(0x3d,len(payload));c.edge(0x74,'ok',1);c.imm(0xb8,98);c.raw(b'\xc3')
        c.label('ok');c.imm(0xb8,0);c.raw(b'\xc3')
    if family==0:
        pairs=[(0xffffffff,1,0),(0xfffffffe,3,1),(0,255,255),(127,1,128),
               (0x7fffffff,1,0x80000000),(0x80000000,0x80000000,0),(1,0xffffffff,0),(17,25,42)]
        a,b,result=pairs[variant]
        c.imm(0xb8,a);c.imm(5,b);c.imm(0x3d,result);c.edge(0x74,'out',1)
        c.imm(0xb8,97);c.raw(b'\xc3');c.label('out');output()
    elif family==1:
        c.imm(0x68,variant);c.edge(0xe8,'outer',4);c.raw(bytes.fromhex('8d642404'))
        c.imm(0x3d,variant+8);c.edge(0x74,'out',1);c.imm(0xb8,96);c.raw(b'\xc3');c.label('out');output()
        c.label('outer');c.raw(bytes.fromhex('8b442404'));c.imm(0x68,variant);c.edge(0xe8,'inner',4)
        c.raw(bytes.fromhex('8d642404'));c.imm(5,3);c.raw(b'\xc3')
        c.label('inner');c.raw(bytes.fromhex('8b442404'));c.imm(5,5);c.raw(b'\xc3')
    elif family==2:
        c.raw(b'\xa1'+struct.pack('<I',0x402080+variant));c.imm(5,variant)
        c.imm(0x3d,100+2*variant);c.edge(0x74,'out',1);c.imm(0xb8,95);c.raw(b'\xc3');c.label('out');output()
    else:
        c.raw(b'\x31\xc0');c.edge(0x74,'alternate',1)
        c.edge(0xe8,'helper',4);c.imm(0xb8,0);c.raw(b'\xc3');c.label('alternate')
        if variant%2==0: c.imm(0xb8,0);c.raw(b'\xc3')
        else: c.edge(0xe8,'helper',4);c.imm(0xb8,0);c.raw(b'\xc3')
        c.label('helper');output()
    code=c.finish();assert len(code)<=256
    b=bytearray(2048)
    def word(at,n,size=4): b[at:at+size]=n.to_bytes(size,'little')
    b[:2]=b'MZ';word(60,128);b[128:132]=b'PE\0\0'
    word(132,0x14c,2);word(134,3,2);word(148,224,2);word(150,0x102,2)
    o=152
    for at,n,size in [(0,0x10b,2),(4,512,4),(8,1024,4),(16,4096,4),(20,4096,4),(24,8192,4),
        (28,0x400000,4),(32,4096,4),(36,512,4),(40,4,2),(48,4,2),(56,16384,4),
        (60,512,4),(68,3,2),(72,1048576,4),(76,4096,4),(80,1048576,4),(84,4096,4),
        (92,16,4),(104,0x3000,4),(108,40,4),(192,iat,4),(196,8,4)]: word(o+at,n,size)
    for i,(namebytes,flags,vs) in enumerate([(b'.text',0x60000020,256),(b'.rdata',0x40000040,256),(b'.idata',0xc0000040,256)]):
        at=376+40*i;b[at:at+len(namebytes)]=namebytes
        for offset,n in [(8,vs),(12,4096*(i+1)),(16,512),(20,512*(i+1)),(36,flags)]:word(at+offset,n)
    b[512:512+len(code)]=code;b[1024+buffer_offset:1024+buffer_offset+len(payload)]=payload
    word(1024+128+variant,100+variant)
    def loc(rva):return 1536+rva-0x3000
    for offset,n in [(0,ilt),(12,dll),(16,iat)]:word(1536+offset,n)
    word(loc(ilt),name);word(loc(iat),name)
    b[loc(dll):loc(dll)+11]=b'msvcrt.dll\0';b[loc(name):loc(name)+9]=b'\0\0_write\0'
    return bytes(b)
