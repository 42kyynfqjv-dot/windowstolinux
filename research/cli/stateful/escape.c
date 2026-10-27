/* Authored freestanding binary stream driver; MIT OR Apache-2.0. */
#include <windows.h>
DWORD WINAPI entry(void) {
 HANDLE in=GetStdHandle(STD_INPUT_HANDLE),out=GetStdHandle(STD_OUTPUT_HANDLE);
 unsigned char input[64],output[256];
 DWORD n,i,used,sent,written; unsigned int state=0; int end;
 if(!in || in==INVALID_HANDLE_VALUE || !out || out==INVALID_HANDLE_VALUE)return 10;
 for(;;){end=0;
  if(!ReadFile(in,input,sizeof(input),&n,0)){if(GetLastError()!=ERROR_BROKEN_PIPE)return 11;n=0;}
  if(n>sizeof(input))return 14;if(!n)end=1;used=0;
  for(i=0;i<n;i++){unsigned char c=input[i];
   if(state){output[used++]=c;state=0;}
   else if(c==92)state=1;else if(c!=124)output[used++]=c;
  }
  if(end && state){output[used++]=92;state=0;}
  sent=0;while(sent<used){if(!WriteFile(out,output+sent,used-sent,&written,0))return 12;if(!written || written>used-sent)return 13;sent+=written;}
  if(end)return 0;
 }
}
