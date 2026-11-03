/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Independently authored installed-code-page observation; no translation. */
#include <windows.h>
static int word(DWORD n){
 const unsigned char *p=(const unsigned char *)&n;DWORD left=4;
 while(left){DWORD written=0;if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),p,left,&written,0)||!written||written>left)return 0;p+=written;left-=written;}return 1;
}
int main(void){
 const UINT pages[2]={65001u,0xffffffffu};unsigned i;
 if(!word(0x31504356)||!word(GetACP())||!word(2))return 2;
 for(i=0;i<2;i++){
  BOOL valid;DWORD error;SetLastError(0x12345678u);valid=IsValidCodePage(pages[i]);error=GetLastError();
  if(!word(pages[i])||!word(valid?1u:0u)||!word(error))return 3;
 }
 return 0;
}
