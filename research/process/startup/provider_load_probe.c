#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
static const wchar_t *base(const wchar_t *p) { const wchar_t *q=wcsrchr(p,L'\\');return q?q+1:p; }
int wmain(int argc,wchar_t **argv) {
 HMODULE fail,ok,second;DWORD first_error,second_error;int before,after_first,after_second,held,absent;unsigned value;
 typedef unsigned (__cdecl *value_fn)(void);value_fn f;
 if(argc!=3||sizeof(void*)!=4)return 2;
 before=GetModuleHandleW(base(argv[1]))==NULL;
 SetLastError(0x1234);fail=LoadLibraryExW(argv[1],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);first_error=GetLastError();
 if(fail){FreeLibrary(fail);return 3;}after_first=GetModuleHandleW(base(argv[1]))==NULL;
 SetLastError(0x5678);fail=LoadLibraryExW(argv[1],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);second_error=GetLastError();
 if(fail){FreeLibrary(fail);return 4;}after_second=GetModuleHandleW(base(argv[1]))==NULL;
 if(GetModuleHandleW(base(argv[2])))return 5;
 ok=LoadLibraryExW(argv[2],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(!ok)return 6;
 second=LoadLibraryExW(argv[2],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if(second!=ok)return 7;
 f=(value_fn)GetProcAddress(ok,"independent_value");if(!f)return 8;value=f();
 if(!FreeLibrary(ok))return 9;held=GetModuleHandleW(base(argv[2]))==second;
 if(!FreeLibrary(second))return 10;absent=GetModuleHandleW(base(argv[2]))==NULL;
 printf("{\"before_absent\":%s,\"first_error\":%lu,\"after_first_absent\":%s,\"second_error\":%lu,\"after_second_absent\":%s,\"value\":%u,\"held_after_one_release\":%s,\"absent_after_final_release\":%s}\n",before?"true":"false",first_error,after_first?"true":"false",second_error,after_second?"true":"false",value,held?"true":"false",absent?"true":"false");return 0;
}
