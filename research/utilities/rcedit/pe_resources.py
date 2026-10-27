"""Read-only PE resource snapshots for authored disposable containers."""
import hashlib,struct

def snapshot(data):
 def get(fmt,at):
  size=struct.calcsize(fmt)
  if at<0 or at+size>len(data):raise ValueError('truncated PE metadata')
  return struct.unpack_from(fmt,data,at)
 if data[:2]!=b'MZ':raise ValueError('not PE')
 pe=get('<I',60)[0]
 if data[pe:pe+4]!=b'PE\0\0':raise ValueError('PE signature')
 machine,count=get('<HH',pe+4);optional=pe+24;size=get('<H',pe+20)[0];magic=get('<H',optional)[0]
 if magic!=0x10b or not 0<count<=32:raise ValueError('fixture profile')
 sections=[]
 for i in range(count):
  at=optional+size+i*40;virtual,rva,n,raw=get('<IIII',at+8)
  if raw+n>len(data):raise ValueError('section bounds')
  sections.append((data[at:at+8].rstrip(b'\0').decode('ascii'),rva,n,raw))
 def location(rva,n):
  matches=[raw+rva-base for _,base,length,raw in sections if base<=rva and rva+n<=base+length]
  if len(matches)!=1:raise ValueError('ambiguous/unbacked resource')
  return matches[0]
 root_rva,root_size=get('<II',optional+112);root=location(root_rva,root_size);resources={};seen=set()
 def within(at,n):
  if not root<=at or at+n>root+root_size:raise ValueError('resource directory range')
 def key(name):
  if not name&0x80000000:return str(name)
  at=root+(name&0x7fffffff);within(at,2);n=get('<H',at)[0];within(at+2,2*n)
  return data[at+2:at+2+2*n].decode('utf-16le')
 def walk(relative,keys):
  if len(keys)>2 or relative in seen:raise ValueError('resource cycle/depth')
  seen.add(relative);at=root+relative;within(at,16);named,ids=get('<HH',at+12);n=named+ids
  if n>1024:raise ValueError('resource budget')
  within(at+16,n*8)
  for i in range(n):
   name,target=get('<II',at+16+8*i);path=keys+[key(name)]
   if target&0x80000000:walk(target&0x7fffffff,path)
   else:
    if len(path)!=3:raise ValueError('resource depth')
    leaf=root+target;within(leaf,16);rva,length,_,_=get('<IIII',leaf);start=location(rva,length);blob=data[start:start+length]
    resources['/'.join(path)]={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':length}
 walk(0,[])
 text=[data[raw:raw+n] for name,_,n,raw in sections if name=='.text']
 if len(text)!=1:raise ValueError('fixture code identity')
 return dict(machine=machine,entry=get('<I',optional+16)[0],code_sha256=hashlib.sha256(text[0]).hexdigest(),resources=resources)
