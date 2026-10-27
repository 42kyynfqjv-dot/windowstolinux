/* Authored substituted-backend probe; MIT OR Apache-2.0. Not original OS execution. */
#include <windows.h>
#include <stdio.h>
static const unsigned char data[]={13,65,9,92,124,13,10,124,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,92,13};
static unsigned char result[2048];static DWORD pos,used,chunk,wchunk,err,mode,reads,writes;
static HANDLE WINAPI probe_handle(DWORD s){return (HANDLE)(ULONG_PTR)(s==STD_INPUT_HANDLE?1:2);}
static DWORD WINAPI probe_error(void){return err;}
static BOOL WINAPI probe_read(HANDLE h,LPVOID b,DWORD cap,LPDWORD n,LPOVERLAPPED ov){DWORD k;(void)h;(void)ov;++reads;*n=0;
 if(mode==20 || (mode==21 && pos>=1)){err=1117;return FALSE;}
 k=(DWORD)sizeof(data)-pos;if(k>chunk)k=chunk;if(k>cap)k=cap;
 if(!k){if(mode<20 && mode%2){err=109;return FALSE;}return TRUE;}
 {DWORD i;for(i=0;i<k;i++)((unsigned char*)b)[i]=data[pos+i];}pos+=k;*n=k;return TRUE;}
static BOOL WINAPI probe_write(HANDLE h,LPCVOID b,DWORD cap,LPDWORD n,LPOVERLAPPED ov){DWORD k=cap,i;(void)h;(void)ov;++writes;*n=0;
 if(mode==22 && used>=2){err=1117;return FALSE;}if(mode==23)return TRUE;
 if(k>wchunk)k=wchunk;if(mode==22 && k>2-used)k=2-used;
 for(i=0;i<k;i++)result[used+i]=((const unsigned char*)b)[i];used+=k;*n=k;return TRUE;}
#define GetStdHandle probe_handle
#define GetLastError probe_error
#define ReadFile probe_read
#define WriteFile probe_write
#define entry filter_entry
#include FILTER_SOURCE
#undef entry
int main(void){static const DWORD chunks[]={1,2,3,63,64};
 for(mode=0;mode<24;mode++){DWORD code,i;pos=used=err=reads=writes=0;
 chunk=mode<20?chunks[mode/4]:mode==21?1:64;wchunk=mode<20?((mode/2)%2?7:1):1;
 code=filter_entry();printf("mode=%lu exit=%lu reads=%lu writes=%lu hex=",mode,code,reads,writes);for(i=0;i<used;i++)printf("%02x",result[i]);printf("\n");}
 return 0;}
