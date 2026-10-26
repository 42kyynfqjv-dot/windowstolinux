/* Scripted API backend around the frozen source. Not original PE execution. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned mode, pos, used, reads, writes;
static const unsigned char data[] = {'a','Z',0,255};
static unsigned char result[16];
static HANDLE WINAPI get_handle(DWORD n) { return mode==1 ? NULL : (HANDLE)(ULONG_PTR)n; }
static BOOL WINAPI read_part(HANDLE h, LPVOID b, DWORD n, LPDWORD got, LPOVERLAPPED o) {
    DWORD take; (void)h;(void)n;(void)o; ++reads;
    if(mode==2) return FALSE;
    if(mode==6){*got=257;return TRUE;}
    if(pos==sizeof(data)){*got=0;return mode==7 ? FALSE : TRUE;}
    take=pos==1 ? 2 : 1; memcpy(b,data+pos,take);pos+=take;*got=take;return TRUE;
}
static BOOL WINAPI write_part(HANDLE h,LPCVOID b,DWORD n,LPDWORD got,LPOVERLAPPED o) {
    (void)h;(void)o;++writes;
    if(mode==3)return FALSE;
    if(mode==4){*got=0;return TRUE;}
    if(mode==5){*got=n+1;return TRUE;}
    result[used++]=*(const unsigned char*)b;*got=1;return TRUE;
}
#define GetStdHandle get_handle
#define ReadFile read_part
#define WriteFile write_part
#define entry scripted_entry
#include "filter.c"
int main(void) {
    const DWORD expected[]={0,10,11,12,13,13,14,11};
    for(mode=0;mode<8;++mode){DWORD exitcode;pos=used=reads=writes=0;memset(result,0,sizeof(result));exitcode=scripted_entry();
        if(exitcode!=expected[mode])return 1;
        if(mode==0||mode==7){if(used!=4||memcmp(result,"AZ\0\xff",4)||reads!=4||writes!=4)return 2;}
        printf("mode=%u exit=%lu read_calls=%u write_calls=%u output_bytes=%u\n",mode,exitcode,reads,writes,used);
    }
    return 0;
}
