/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Independently authored Windows API/CRT observation, not translated execution. */
#include <windows.h>
#include <wchar.h>
static int send_bytes(const void *p,DWORD size){
 const unsigned char *bytes=(const unsigned char*)p;HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
 while(size){DWORD written=0;if(!WriteFile(output,bytes,size,&written,0)||!written||written>size)return 0;bytes+=written;size-=written;}return 1;
}
static int word(DWORD n){return send_bytes(&n,4);}
static DWORD alen(const char *p){DWORD n=0;while(n<131068&&p[n])n++;return n;}
static DWORD wlen(const wchar_t *p){DWORD n=0;while(n<32767&&p[n])n++;return n;}
static int buffer(const void *p,DWORD n){return word(n)&&send_bytes(p,n);}
int wmain(int argc,wchar_t **argv){
 const char *a=GetCommandLineA();const wchar_t *w=GetCommandLineW();DWORD n,i,stable;
 if(!a||!w||argc<0||argc>32767)return 2;
 stable=(a==GetCommandLineA()?1u:0u)|(w==GetCommandLineW()?2u:0u);
 if(!word(0x31444d43)||!word(GetACP())||!word(stable))return 3;
 n=alen(a);if(n==131068||!buffer(a,n+1))return 4;
 n=wlen(w);if(n==32767||!buffer(w,(n+1)*2))return 5;
 if(!word((DWORD)argc))return 6;
 for(i=0;i<(DWORD)argc;i++){n=wlen(argv[i]);if(n==32767||!buffer(argv[i],(n+1)*2))return 7;}
 return 0;
}
