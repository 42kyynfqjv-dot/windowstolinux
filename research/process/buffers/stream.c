/* Independently authored conformance, MIT OR Apache-2.0. Custom entry. */
#include <windows.h>
DWORD WINAPI entry(void) {
 HANDLE heap=GetProcessHeap(),in=GetStdHandle(STD_INPUT_HANDLE),out=GetStdHandle(STD_OUTPUT_HANDLE);
 unsigned char *p=HeapAlloc(heap,0,64); DWORD got,sent,n,i;
 if(!p)return 12;
 for(;;){
  if(!ReadFile(in,p,64,&got,0)){HeapFree(heap,0,p);return 11;}
  if(!got)break;
  for(i=0;i<got;i++)p[i]^=32;
  sent=0;
  while(sent<got){
   if(!WriteFile(out,p+sent,got-sent,&n,0)){HeapFree(heap,0,p);return 14;}
   if(!n||n>got-sent){HeapFree(heap,0,p);return 15;}sent+=n;
  }
 }
 return HeapFree(heap,0,p)?0:16;
}
