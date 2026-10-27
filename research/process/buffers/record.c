/* Independently authored conformance, MIT OR Apache-2.0. Custom entry. */
#include <windows.h>
DWORD WINAPI entry(void) {
 HANDLE heap=GetProcessHeap(),in=GetStdHandle(STD_INPUT_HANDLE),out=GetStdHandle(STD_OUTPUT_HANDLE);
 DWORD *p=HeapAlloc(heap,0,8),got,n,sent=0;
 if(!p)return 12;
 if(!ReadFile(in,p,8,&got,0)||got!=8){HeapFree(heap,0,p);return 11;}
 p[0]=p[0]+p[1];
 while(sent<4){
  if(!WriteFile(out,((unsigned char*)p)+sent,4-sent,&n,0)){HeapFree(heap,0,p);return 14;}
  if(!n||n>4-sent){HeapFree(heap,0,p);return 15;}sent+=n;
 }
 return HeapFree(heap,0,p)?0:16;
}
