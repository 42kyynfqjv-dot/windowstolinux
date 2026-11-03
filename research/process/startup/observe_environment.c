/* Authored synthetic-only process environment observations. MIT OR Apache-2.0. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
typedef char Pe32EnvironmentLayout[(sizeof(void*)==4 && sizeof(WCHAR)==2)?1:-1];
static int inspect(const WCHAR *p, int empty, unsigned *count, unsigned *units) {
    const WCHAR *s=p; unsigned n=0,seen=0;
    while(*s) {
        size_t k=wcslen(s);
        if(k>1024 || ++n>8) return 0;
        unsigned bit=wcscmp(s,L"W2L_ALPHA=one")==0?1u:wcscmp(s,L"W2L_EMPTY=")==0?2u:wcscmp(s,L"W2L_UNICODE=\x96ea\xd83d\xde00")==0?4u:0u;
        if(!bit || (seen&bit)) return 0; seen|=bit;
        s+=k+1;
    }
    *count=n; *units=n?(unsigned)(s-p)+1:(p[1]==0?2u:1u);
    return empty?n==0:n==3&&seen==7;
}
int main(int argc,char **argv) {
    WCHAR *a,*b; unsigned n=0,units=0,n2=0,u2=0; BOOL fa,fb; DWORD ge,fe;
    int empty=argc==2 && strcmp(argv[1],"empty")==0; int stable,distinct;
    setvbuf(stdout,NULL,_IONBF,0);
    SetLastError(0x1234); a=GetEnvironmentStringsW(); ge=GetLastError(); b=GetEnvironmentStringsW();
    if(!a||!b) return 10;
    if(!inspect(a,empty,&n,&units)||!inspect(b,empty,&n2,&u2)) return 11;
    if(!SetEnvironmentVariableW(L"W2L_ALPHA",L"changed")) return 12;
    stable=inspect(a,empty,&n2,&u2);
    distinct=a!=b;
    SetLastError(0x2345);fa=FreeEnvironmentStringsW(a);fe=GetLastError();fb=distinct?FreeEnvironmentStringsW(b):FALSE;
    printf("{\"case\":\"%s\",\"entries\":%u,\"units\":%u,\"distinct_live\":%s,\"stable_after_mutation\":%s,\"free_first\":%s,\"free_second\":%s,\"get_last_error\":%lu,\"free_last_error\":%lu,\"compiler\":%lu}\n",empty?"empty":"synthetic",n,units,distinct?"true":"false",stable?"true":"false",fa?"true":"false",fb?"true":"false",ge,fe,(unsigned long)_MSC_FULL_VER);
    return fa&&fb&&stable?0:13;
}
