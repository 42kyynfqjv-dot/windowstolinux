#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
/* Authored read-only query of two Windows system modules from the original
   resolver candidate list. No third-party DLL or callback is executed. */
static int path(HMODULE m){wchar_t p[32768],final[32768];DWORD n,i;HANDLE f;n=GetModuleFileNameW(m,p,32768);if(!n||n>=32768)return 0;f=CreateFileW(p,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return 0;n=GetFinalPathNameByHandleW(f,final,32768,FILE_NAME_NORMALIZED);CloseHandle(f);if(!n||n>=32768)return 0;for(i=0;i<n;i++)printf("%02x%02x",final[i]&255,final[i]>>8);return 1;}
int main(void) {
    const WCHAR *names[] = {L"api-ms-win-core-fibers-l1-1-2", L"kernelbase"};
    unsigned i;
    if (sizeof(void *) != 4) return 2;
    for (i = 0; i < 2; ++i) {
        HMODULE module;
        FARPROC function = NULL;
        DWORD load_error, lookup_error = 0;
        BOOL released = FALSE;
        SetLastError(0x12345678);
        module = LoadLibraryExW(names[i], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        load_error = GetLastError();
        if (module) {
            SetLastError(0x87654321);
            function = GetProcAddress(module, "FlsGetValue2");
            lookup_error = GetLastError();

        }
        printf("{\"load_host_utf16\":\"");
        if (module && !path(module)) return 4;
        if (module) released = FreeLibrary(module);
        printf("\",\"candidate\":%u,\"loaded\":%s,\"load_error\":%lu,\"found\":%s,\"lookup_error\":%lu,\"released\":%s}\n",
            i, module ? "true" : "false", load_error,
            function ? "true" : "false", lookup_error, released ? "true" : "false");
        if (module && !FreeLibrary(module)) return 3;
    }
    return 0;
}
