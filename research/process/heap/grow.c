/* Authored allocation/growth conformance. MIT OR Apache-2.0.
 * Custom entry, bounded regular-file input/output; no CRT startup replacement. */
#include <windows.h>
DWORD WINAPI entry(void) {
    unsigned char input[2]; DWORD got, sent, done, i, n, extra; unsigned char *p,*q;
    HANDLE h=GetProcessHeap(), in=GetStdHandle(STD_INPUT_HANDLE), out=GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h!=GetProcessHeap()) return 10;
    if (!ReadFile(in,input,2,&got,0) || got!=2) return 11;
    n=1+(input[0]&31); extra=1+(input[1]&15);
    p=(unsigned char *)HeapAlloc(h,0,n); if (!p) return 12;
    if (((ULONG_PTR)p&7)!=0) return 20;
    for(i=0;i<n;++i) p[i]=(unsigned char)(17*i+input[0]);
    q=(unsigned char *)HeapReAlloc(h,HEAP_ZERO_MEMORY,p,n+extra);
    if (!q) { HeapFree(h,0,p); return 13; }
    if (((ULONG_PTR)q&7)!=0) return 20;
    for(i=n;i<n+extra;++i) if(q[i]!=0) return 21;
    sent=0;
    while(sent<n+extra) {
        if(!WriteFile(out,q+sent,n+extra-sent,&done,0)) { HeapFree(h,0,q); return 14; }
        if(!done || done>n+extra-sent) { HeapFree(h,0,q); return 15; }
        sent+=done;
    }
    return HeapFree(h,0,q) ? 0 : 16;
}
