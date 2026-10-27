/* Independent Win32 resource oracle; MIT OR Apache-2.0. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
static void text(const char *name, const WCHAR *s) {
 printf("%s=",name); while (*s) printf("%04x",(unsigned)*s++); printf("\n");
}
int wmain(int argc, WCHAR **argv) {
 DWORD unused=0, size; UINT length=0; VS_FIXEDFILEINFO *fixed=NULL;
 WCHAR *value=NULL, string[512]; void *data; HMODULE module; HRSRC resource; HGLOBAL loaded;
 const unsigned char *bytes; DWORD n;
 if(argc!=2) return 2;
 size=GetFileVersionInfoSizeW(argv[1],&unused); if(!size)return 3;
 data=malloc(size); if(!data)return 4;
 if(!GetFileVersionInfoW(argv[1],0,size,data))return 5;
 if(!VerQueryValueW(data,L"\\",(void**)&fixed,&length) || length<sizeof(*fixed))return 6;
 printf("FILE=%u.%u.%u.%u\n",HIWORD(fixed->dwFileVersionMS),LOWORD(fixed->dwFileVersionMS),HIWORD(fixed->dwFileVersionLS),LOWORD(fixed->dwFileVersionLS));
 printf("PRODUCT=%u.%u.%u.%u\n",HIWORD(fixed->dwProductVersionMS),LOWORD(fixed->dwProductVersionMS),HIWORD(fixed->dwProductVersionLS),LOWORD(fixed->dwProductVersionLS));
 if(!VerQueryValueW(data,L"\\StringFileInfo\\040904b0\\ProductName",(void**)&value,&length))return 7;
 text("NAME",value);
 if(!VerQueryValueW(data,L"\\StringFileInfo\\040904b0\\FileVersion",(void**)&value,&length))return 8;
 text("FILESTRING",value);free(data);
 module=LoadLibraryExW(argv[1],NULL,LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE); if(!module)return 9;
 if(!LoadStringW(module,42,string,512))return 10;text("STRING42",string);
 resource=FindResourceW(module,MAKEINTRESOURCEW(77),MAKEINTRESOURCEW(10));if(!resource)return 11;
 n=SizeofResource(module,resource);loaded=LoadResource(module,resource);if(!loaded)return 12;
 bytes=(const unsigned char*)LockResource(loaded);if(!bytes)return 13;
 printf("RCDATA=");for(DWORD i=0;i<n;i++)printf("%02x",bytes[i]);printf("\n");
 FreeLibrary(module);return 0;
}
