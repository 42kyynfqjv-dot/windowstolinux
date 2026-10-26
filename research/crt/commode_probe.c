/* Authored isolated internal-interface research. MIT OR Apache-2.0. */
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
extern int * __cdecl __p__commode(void);
static int *thread_pointer;
static int thread_value;
static unsigned __stdcall observe(void *unused) {
    (void)unused; thread_pointer=__p__commode();
    if(!thread_pointer) return 1;
    thread_value=*thread_pointer; return 0;
}
int main(void) {
    int *p=__p__commode(), *again; int original, observed, restored;
    uintptr_t handle; DWORD code; HMODULE owner; MEMORY_BASIC_INFORMATION region;
    char path[32768]; DWORD n;
    if(!p || (uintptr_t)p%4) return 90;
    if(VirtualQuery(p,&region,sizeof(region))!=sizeof(region) || region.State!=MEM_COMMIT || region.Protect&PAGE_GUARD || (region.Protect&255)!=PAGE_READWRITE || (uintptr_t)p+4>(uintptr_t)region.BaseAddress+region.RegionSize) return 91;
    if(!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)p,&owner)) return 92;
    n=GetModuleFileNameA(owner,path,sizeof(path));if(!n || n>=sizeof(path))return 93;
    original=*p; *p=0; again=__p__commode(); observed=again?*again:-1;
    handle=_beginthreadex(NULL,0,observe,NULL,0,NULL);
    if(!handle){*p=original;return 94;}
    /* No racing access: main reads worker results only after joining it. */
    if(WaitForSingleObject((HANDLE)handle,5000)!=WAIT_OBJECT_0) { CloseHandle((HANDLE)handle); ExitProcess(95); }
    if(!GetExitCodeThread((HANDLE)handle,&code)){*p=original;CloseHandle((HANDLE)handle);return 96;}
    CloseHandle((HANDLE)handle);*p=original;restored=*p;
    printf("%lu %lu %lu %lu %d %d %d %d %lu\n",(unsigned long)(uintptr_t)p,(unsigned long)(uintptr_t)again,(unsigned long)(uintptr_t)thread_pointer,(unsigned long)(uintptr_t)owner,original,observed,thread_value,restored,(unsigned long)code);
    fprintf(stderr,"OWNER\t%s\n",path);
    return again==p && thread_pointer==p && observed==0 && thread_value==0 && restored==original && code==0 ? 0:97;
}
