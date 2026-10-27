/* Authored two-object shrinking/reversal conformance. MIT OR Apache-2.0. */
#include <windows.h>
DWORD WINAPI entry(void) {
    unsigned char input[2]; DWORD got, sent, done, i, n, k; unsigned char *p,*q,*r;
    HANDLE h=GetProcessHeap(), in=GetStdHandle(STD_INPUT_HANDLE), out=GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h!=GetProcessHeap()) return 10;
    if (!ReadFile(in,input,2,&got,0) || got!=2) return 11;
    n=1+(input[0]&31); k=n/2+1;
    p=(unsigned char *)HeapAlloc(h,HEAP_ZERO_MEMORY,n); if(!p) return 12;
    q=(unsigned char *)HeapAlloc(h,0,k); if(!q) { HeapFree(h,0,p); return 12; }
    if ((((ULONG_PTR)p|(ULONG_PTR)q)&7)!=0) return 20;
    for(i=0;i<n;++i) { if(p[i]!=0) return 21; p[i]=(unsigned char)(input[1]+3*i); }
    r=(unsigned char *)HeapReAlloc(h,0,p,k); if(!r) { HeapFree(h,0,p); HeapFree(h,0,q); return 13; }
    for(i=0;i<k;++i) q[i]=r[k-i-1];
    if(!HeapFree(h,0,r)) return 16;
    sent=0;
    while(sent<k) {
        if(!WriteFile(out,q+sent,k-sent,&done,0)) { HeapFree(h,0,q); return 14; }
        if(!done || done>k-sent) { HeapFree(h,0,q); return 15; }
        sent+=done;
    }
    return HeapFree(h,0,q) ? 0 : 16;
}
