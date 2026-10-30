#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
static const wchar_t *names[]={L"api-ms-win-core-synch-l1-2-0",L"api-ms-win-core-fibers-l1-1-1",L"api-ms-win-core-heap-l1-1-0",L"api-ms-w2l-missing-contract-l9-9-9"};
static const char *symbols[]={"InitializeCriticalSectionEx","FlsAlloc","HeapAlloc","NoSuchExport"};
static int path(HMODULE m){wchar_t p[32768],final[32768];DWORD n,i;HANDLE f;n=GetModuleFileNameW(m,p,32768);if(!n||n>=32768)return 0;f=CreateFileW(p,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return 0;n=GetFinalPathNameByHandleW(f,final,32768,FILE_NAME_NORMALIZED);CloseHandle(f);if(!n||n>=32768)return 0;for(i=0;i<n;i++)printf("%02x%02x",final[i]&255,final[i]>>8);return 1;}
int main(int argc,char **argv){int index;HMODULE a,b,owner=NULL;FARPROC x,y;DWORD error;
 if(argc!=2)return 2;index=atoi(argv[1]);if(index<0||index>3||sizeof(void*)!=4)return 3;
 SetLastError(0);a=LoadLibraryExW(names[index],NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);error=GetLastError();
 if(!a){printf("{\"loaded\":false,\"error\":%lu}\n",error);return 0;}
 b=LoadLibraryExW(names[index],NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!b){FreeLibrary(a);return 4;}
 x=GetProcAddress(a,symbols[index]);if(!x){FreeLibrary(b);FreeLibrary(a);return 5;}
 if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)x,&owner)){FreeLibrary(b);FreeLibrary(a);return 6;}
 printf("{\"loaded\":true,\"same_handle\":%s,\"load_host_utf16\":\"",a==b?"true":"false");if(!path(a))return 7;
 printf("\",\"export_host_utf16\":\"");if(!path(owner))return 8;
 if(!FreeLibrary(a))return 9;y=GetProcAddress(b,symbols[index]);
 printf("\",\"export_survives_one_release\":%s,\"ntdll_utf16\":\"",y==x?"true":"false");if(!path(GetModuleHandleW(L"ntdll.dll")))return 10;
 printf("\"}\n");if(!FreeLibrary(owner)||!FreeLibrary(b))return 11;return 0;
}
