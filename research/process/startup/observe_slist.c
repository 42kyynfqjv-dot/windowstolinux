/* Authored bounded public-API probe. MIT OR Apache-2.0. No PE translation. */
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>
typedef VOID (WINAPI *InitHead)(PSLIST_HEADER);
typedef char Pe32SListLayout[(sizeof(void*)==4 && sizeof(SLIST_HEADER)==8)?1:-1];
static void bytes(const unsigned char *p, size_t n) {
    size_t i; putchar('['); for (i=0;i<n;i++) printf("%s%u",i?",":"",(unsigned)p[i]); putchar(']');
}
int main(void) {
    HMODULE kernel=GetModuleHandleW(L"kernel32.dll"); FARPROC raw;
    InitHead initialize; unsigned pattern, offset; unsigned cases=0;
    setvbuf(stdout,NULL,_IONBF,0);
    if (!kernel) return 10;
    raw=GetProcAddress(kernel,"InitializeSListHead");
    if (!raw || sizeof(initialize)!=sizeof(raw)) return 11;
    memcpy(&initialize,&raw,sizeof(initialize));
    printf("{\"kind\":\"original Windows InitializeSListHead PE32 API observations; no PE translation\",\"pointer_bytes\":%u,\"header_bytes\":%u,\"compiler\":%lu}\n",(unsigned)sizeof(void*),(unsigned)sizeof(SLIST_HEADER),(unsigned long)_MSC_FULL_VER);
    for (pattern=0;pattern<4;pattern++) for (offset=16;offset<=32;offset+=8) {
        __declspec(align(16)) unsigned char storage[64];
        unsigned char initial[64], after[64]; PSLIST_HEADER head;
        PSLIST_ENTRY popped; USHORT depth; unsigned i; int guard=1;
        for (i=0;i<64;i++) storage[i]=(unsigned char)(pattern==0?0:pattern==1?255:pattern==2?165:i);
        memcpy(initial,storage,sizeof(storage)); head=(PSLIST_HEADER)(storage+offset);
        initialize(head); memcpy(after,storage,sizeof(storage)); depth=QueryDepthSList(head);
        popped=InterlockedPopEntrySList(head);
        for(i=0;i<64;i++) if ((i<offset || i>=offset+sizeof(SLIST_HEADER)) && storage[i]!=initial[i]) guard=0;
        printf("{\"case\":%u,\"pattern\":%u,\"offset\":%u,\"initial\":",cases,pattern,offset);bytes(initial+offset,sizeof(SLIST_HEADER));
        printf(",\"initialized\":");bytes(after+offset,sizeof(SLIST_HEADER));printf(",\"after_empty_pop\":");bytes(storage+offset,sizeof(SLIST_HEADER));
        printf(",\"depth\":%u,\"empty_pop_null\":%s,\"guards_unchanged\":%s}\n",(unsigned)depth,popped==NULL?"true":"false",guard?"true":"false");cases++;
    }
    return cases==12?0:13;
}
