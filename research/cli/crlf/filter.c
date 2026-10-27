/* Authored streaming normalizer. MIT OR Apache-2.0. Freestanding x86 entry. */
#include <windows.h>
DWORD WINAPI entry(void) {
 HANDLE in=GetStdHandle(STD_INPUT_HANDLE), out=GetStdHandle(STD_OUTPUT_HANDLE);
 unsigned char input[128], output[129];
 DWORD n,i,used,sent,written; int pending=0, end;
 if(!in || in==INVALID_HANDLE_VALUE || !out || out==INVALID_HANDLE_VALUE) return 10;
 for(;;) {
  end=0;
  if(!ReadFile(in,input,sizeof(input),&n,0)) {
   if(GetLastError()!=ERROR_BROKEN_PIPE) return 11;
   n=0;
  }
  if(n>sizeof(input)) return 14;
  if(!n) end=1;
  used=0;
  for(i=0;i<n;i++) {
   unsigned char c=input[i];
   if(pending) {
    pending=0;
    if(c==10) {output[used++]=10;continue;}
    output[used++]=13;
   }
   if(c==13) pending=1; else output[used++]=c;
  }
  if(end && pending) {output[used++]=13;pending=0;}
  sent=0;
  while(sent<used) {
   if(!WriteFile(out,output+sent,used-sent,&written,0)) return 12;
   if(!written || written>used-sent) return 13;
   sent+=written;
  }
  if(end) return 0;
 }
}
