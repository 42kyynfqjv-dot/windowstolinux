/* Own-child x86 debugger observation. One temporary INT3 byte at original entry,
 * restored before termination; the PE file is never modified. No privilege or
 * security-setting changes or unrelated process access. Not a normal baseline. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static BOOL read_exact(HANDLE process, DWORD address, void *out, SIZE_T n) {
    SIZE_T done=0;
    return ReadProcessMemory(process,(void *)(uintptr_t)address,out,n,&done) && done==n;
}
int main(int argc,char **argv) {
    STARTUPINFOA si={0}; PROCESS_INFORMATION pi={0}; DEBUG_EVENT ev={0};
    DWORD entry=0,base=0,result=125; BOOL armed=FALSE,stopped=FALSE;
    BYTE original=0,trap=0xcc; SIZE_T written=0;
    ULONGLONG deadline=GetTickCount64()+10000;
    if(argc!=3) return 125;
    si.cb=sizeof(si);
    if(!CreateProcessA(argv[1],NULL,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,
                       NULL,NULL,&si,&pi)) return 125;
    unsigned events=0;
    while(events++<128 && GetTickCount64()<deadline && WaitForDebugEvent(&ev,1000)) {
        fprintf(stderr,"event=%lu thread=%lu code=%lu armed=%d\n",ev.dwDebugEventCode,ev.dwThreadId,ev.dwDebugEventCode==EXCEPTION_DEBUG_EVENT?ev.u.Exception.ExceptionRecord.ExceptionCode:0,armed);
        DWORD action=DBG_CONTINUE;
        if(ev.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) {
            base=(DWORD)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            entry=base+(DWORD)strtoul(argv[2],NULL,0);
            if(ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
        } else if(ev.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT) {
            if(ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        } else if(ev.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT) {
            CloseHandle(ev.u.CreateThread.hThread);
        } else if(ev.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) {
            CONTEXT c={0}; c.ContextFlags=CONTEXT_FULL|CONTEXT_DEBUG_REGISTERS;
            DWORD code=ev.u.Exception.ExceptionRecord.ExceptionCode;
            action=DBG_EXCEPTION_NOT_HANDLED;
            if(ev.dwThreadId==pi.dwThreadId && code==EXCEPTION_BREAKPOINT && !armed) {
                if(!entry || !read_exact(pi.hProcess,entry,&original,1) || original==0xcc) break;
                if(!WriteProcessMemory(pi.hProcess,(void *)(uintptr_t)entry,&trap,1,&written) || written!=1 ||
                   !FlushInstructionCache(pi.hProcess,(void *)(uintptr_t)entry,1)) break;
                armed=TRUE;action=DBG_CONTINUE;
            } else if(ev.dwThreadId==pi.dwThreadId && code==EXCEPTION_BREAKPOINT && armed &&
                      (DWORD)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress==entry) {
                LDT_ENTRY selector={0}; DWORD tib[3]={0},record[2]={0};
                MEMORY_BASIC_INFORMATION memory={0};
                if(!GetThreadContext(pi.hThread,&c) || c.Eip!=entry+1 ||
                   !GetThreadSelectorEntry(pi.hThread,c.SegFs,&selector)) break;
                DWORD teb=selector.BaseLow | ((DWORD)selector.HighWord.Bytes.BaseMid<<16) |
                          ((DWORD)selector.HighWord.Bytes.BaseHi<<24);
                if(!read_exact(pi.hProcess,teb,tib,sizeof(tib))) break;
                if(tib[0]!=0xffffffff) {
                    if(!read_exact(pi.hProcess,tib[0],record,sizeof(record)) ||
                       !VirtualQueryEx(pi.hProcess,(void *)(uintptr_t)record[1],&memory,sizeof(memory))) break;
                }
                printf("{\"kind\":\"INT3 entry observation; eip normalized from trap; not baseline\","
                       "\"image_base\":%lu,\"entry\":%lu,\"eip\":%lu,\"esp\":%lu,\"ebp\":%lu,"
                       "\"teb\":%lu,\"stack_base\":%lu,\"stack_limit\":%lu,\"chain_head\":%lu,"
                       "\"previous\":%lu,\"handler\":%lu,\"handler_allocation\":%lu,\"handler_type\":%lu}\n",
                       base,entry,c.Eip-1,c.Esp,c.Ebp,teb,tib[1],tib[2],tib[0],record[0],record[1],
                       (DWORD)(uintptr_t)memory.AllocationBase,memory.Type);
                fflush(stdout); result=0;stopped=TRUE;break;
            }
        } else if(ev.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
            fprintf(stderr,"child exit=%lu\n",ev.u.ExitProcess.dwExitCode);
            ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE);break;
        }
        if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,action)) break;
    }
    /* Never let the measured utility continue into its workload. Drain the owned
     * child's termination event, including failures while an event was pending. */
    fprintf(stderr,"observation stopped=%d result=%lu error=%lu entry=%lu events=%u\n",stopped,result,GetLastError(),entry,events);
    if(armed && (!WriteProcessMemory(pi.hProcess,(void *)(uintptr_t)entry,&original,1,&written) || written!=1 ||
                 !FlushInstructionCache(pi.hProcess,(void *)(uintptr_t)entry,1))) result=125;
    TerminateProcess(pi.hProcess,125);
    ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE);
    for(int i=0;i<32 && WaitForDebugEvent(&ev,100);++i) {
        if(ev.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        if(ev.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT) CloseHandle(ev.u.CreateThread.hThread);
        BOOL exited=ev.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT;
        ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE);
        if(exited) break;
    }
    if(WaitForSingleObject(pi.hProcess,1000)!=WAIT_OBJECT_0) result=125;
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    return stopped?(int)result:125;
}
