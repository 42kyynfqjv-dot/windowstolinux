/* Independently authored user-mode process-boundary observations.
 * No copied runtime source. The installed callback is ours; no loader patch. */
#include <windows.h>

static char mode;
static unsigned visits;
static void mark(char c) {
    DWORD count=0;
    if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),&c,1,&count,NULL) || count!=1)
        ExitProcess(125);
}
static LONG WINAPI root(EXCEPTION_POINTERS *p) {
    if(p->ExceptionRecord->ExceptionCode!=0xe0420042 || ++visits!=1)
        ExitProcess(126);
    mark('T');
    if(mode=='t') ExitProcess(37);
    if(mode!='r') ExitProcess(127);
    return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG frame(DWORD code) {
    if(code!=0xe0420042) return EXCEPTION_CONTINUE_SEARCH;
    mark('F');
    return EXCEPTION_EXECUTE_HANDLER;
}
int main(int argc,char **argv) {
    if(argc!=2 || (argv[1][0]!='r' && argv[1][0]!='t' && argv[1][0]!='s')) return 124;
    mode=argv[1][0];
    SetUnhandledExceptionFilter(root);
    if(mode=='s') {
        __try { RaiseException(0xe0420042,0,0,NULL);mark('X'); }
        __except(frame(GetExceptionCode())) { mark('H'); }
        return visits?123:0;
    }
    RaiseException(0xe0420042,0,0,NULL);
    if(visits!=1) return 122;
    mark('R');
    return 0;
}
