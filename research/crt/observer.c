/* Test-only external observer; never writes the target's memory or artifact.
 * Contract: Microsoft CREATE_PROCESS_DEBUG_INFO.lpBaseOfImage / WaitForDebugEvent.
 * MIT OR Apache-2.0. Own child only; no debug privilege or security changes. */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
int main(int argc, char **argv) {
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0}; DEBUG_EVENT ev;
    FILE *report = NULL; int first_break = 1; DWORD result = 125; ULONGLONG start = GetTickCount64();
    if (argc != 3 || fopen_s(&report, argv[2], "w")) return 125;
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) { fclose(report); return 125; }
    for (;;) {
        DWORD action = DBG_CONTINUE;
        if (GetTickCount64()-start > 15000) { TerminateProcess(pi.hProcess,125); break; }
        if (!WaitForDebugEvent(&ev,1000)) {
            if (GetLastError()==ERROR_SEM_TIMEOUT) continue;
            TerminateProcess(pi.hProcess,125); break;
        }
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            fprintf(report, "BASE\t%lu\n", (unsigned long)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage);
            fflush(report);
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
        } else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            char path[32768]; DWORD n=0;
            if (ev.u.LoadDll.hFile) {
                n=GetFinalPathNameByHandleA(ev.u.LoadDll.hFile,path,sizeof(path),FILE_NAME_NORMALIZED);
                CloseHandle(ev.u.LoadDll.hFile);
            }
            if (!n || n>=sizeof(path)) strcpy_s(path,sizeof(path),"UNRESOLVED");
            fprintf(report,"DLL\t%lu\t%s\n",(unsigned long)(uintptr_t)ev.u.LoadDll.lpBaseOfDll,path);
            fflush(report);
        /* Debug-event process/thread handles are closed by Windows on the
         * corresponding continued EXIT event. Keep our PROCESS_INFORMATION
         * handles separate and close those at the end (WaitForDebugEvent docs). */
        } else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (first_break && ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                first_break = 0;
            else action = DBG_EXCEPTION_NOT_HANDLED;
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            result = ev.u.ExitProcess.dwExitCode;
            if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, action)) result = 125;
            break;
        }
        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, action)) {
            TerminateProcess(pi.hProcess,125); break;
        }
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); fclose(report);
    return (int)result;
}
