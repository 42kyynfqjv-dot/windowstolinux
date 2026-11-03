#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
static LONG WINAPI first(EXCEPTION_POINTERS *p) {(void)p; return EXCEPTION_CONTINUE_SEARCH;}
static LONG WINAPI second(EXCEPTION_POINTERS *p) {(void)p; return EXCEPTION_EXECUTE_HANDLER;}
int main(void) {
    unsigned checks[7];
    LPTOP_LEVEL_EXCEPTION_FILTER saved = SetUnhandledExceptionFilter(NULL);
    checks[0] = 0x31524655;
    checks[1] = first != second;
    checks[2] = SetUnhandledExceptionFilter(first) == NULL;
    checks[3] = SetUnhandledExceptionFilter(second) == first;
    checks[4] = SetUnhandledExceptionFilter(second) == second;
    checks[5] = SetUnhandledExceptionFilter(NULL) == second;
    checks[6] = SetUnhandledExceptionFilter(saved) == NULL;
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
    if (fwrite(checks, sizeof(checks), 1, stdout) != 1) return 3;
    return 0;
}
