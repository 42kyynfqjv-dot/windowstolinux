#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
/* Authored read-only query of two Windows system modules from the original
   resolver candidate list. No third-party DLL or callback is executed. */
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
            released = FreeLibrary(module);
        }
        printf("{\"candidate\":%u,\"loaded\":%s,\"load_error\":%lu,\"found\":%s,\"lookup_error\":%lu,\"released\":%s}\n",
            i, module ? "true" : "false", load_error,
            function ? "true" : "false", lookup_error, released ? "true" : "false");
        if (module && !released) return 3;
    }
    return 0;
}
