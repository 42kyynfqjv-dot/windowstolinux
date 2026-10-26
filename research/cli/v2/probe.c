/* Scripted API backend around the frozen source. Not original PE execution. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
static DWORD last_error;
static unsigned mode, pos, used, reads, writes, bad_argument, remaining;
static unsigned char *next_write;
static const unsigned char data[] = {'a','Z',0,255};
static unsigned char result[16];
static HANDLE WINAPI get_handle(DWORD n) { if(n!=STD_INPUT_HANDLE && n!=STD_OUTPUT_HANDLE)bad_argument=1; return mode==1 ? NULL : (HANDLE)(ULONG_PTR)n; }
static BOOL WINAPI read_part(HANDLE h, LPVOID b, DWORD n, LPDWORD got, LPOVERLAPPED o) {
    DWORD take; ++reads;
    if(h!=(HANDLE)(ULONG_PTR)STD_INPUT_HANDLE || n!=256 || o || remaining)bad_argument=1;
    if(mode==2){last_error=ERROR_ACCESS_DENIED;return FALSE;}
    if(mode==9){last_error=ERROR_BROKEN_PIPE;return FALSE;}
    if(mode==6){*got=257;return TRUE;}
    if(pos==sizeof(data)){*got=0;last_error=mode==7 ? ERROR_BROKEN_PIPE : ERROR_ACCESS_DENIED;return (mode==7 || mode==8) ? FALSE : TRUE;}
    take=pos==1 ? 2 : 1; remaining=take;next_write=(unsigned char*)b;memcpy(b,data+pos,take);pos+=take;*got=take;return TRUE;
}
static BOOL WINAPI write_part(HANDLE h,LPCVOID b,DWORD n,LPDWORD got,LPOVERLAPPED o) {
    ++writes;
    if(h!=(HANDLE)(ULONG_PTR)STD_OUTPUT_HANDLE || o || n!=remaining || b!=next_write)bad_argument=1;
    if(mode==3)return FALSE;
    if(mode==4){*got=0;return TRUE;}
    if(mode==5){*got=n+1;return TRUE;}
    result[used++]=*(const unsigned char*)b;++next_write;--remaining;*got=1;return TRUE;
}
static DWORD WINAPI get_error(void) { return last_error; }
#define GetLastError get_error
#define GetStdHandle get_handle
#define ReadFile read_part
#define WriteFile write_part
#define entry scripted_entry
#include "filter.c"
int main(void) {
    const DWORD expected[]={0,10,11,12,13,13,14,0,11,0};
    for(mode=0;mode<10;++mode){DWORD exitcode;last_error=0;pos=used=reads=writes=bad_argument=remaining=0;memset(result,0,sizeof(result));exitcode=scripted_entry();
        if(exitcode!=expected[mode] || bad_argument)return 1;
        if(mode==0||mode==7||mode==8){if(used!=4||memcmp(result,"AZ\0\xff",4)||reads!=4||writes!=4)return 2;}
        printf("mode=%u exit=%lu read_calls=%u write_calls=%u output_bytes=%u\n",mode,exitcode,reads,writes,used);
    }
    return 0;
}
