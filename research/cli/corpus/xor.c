/* Independently authored corpus application; MIT OR Apache-2.0.
   Freestanding x86 entry; synchronous regular-file/byte-pipe contract. */
#include <windows.h>
DWORD WINAPI entry(void) {
 HANDLE in=GetStdHandle(STD_INPUT_HANDLE), out=GetStdHandle(STD_OUTPUT_HANDLE);
 unsigned char bytes[384]; DWORD n, i, size, pos, done;
 if (!in || in==INVALID_HANDLE_VALUE || !out || out==INVALID_HANDLE_VALUE) return 10;
 for (;;) {
  if (!ReadFile(in,bytes,sizeof(bytes),&n,0)) return GetLastError()==ERROR_BROKEN_PIPE ? 0:11;
  if(n>sizeof(bytes)) return 14;
  if(n==0) return 0;
  size=n;
  i=n;
  while(i!=0) { --i; bytes[i]^=0x5a; }
  pos=0;
  while(pos<size) {
   if(!WriteFile(out,bytes+pos,size-pos,&done,0)) return 12;
   if(done==0 || done>size-pos) return 13;
   pos+=done;
  }
 }
}
