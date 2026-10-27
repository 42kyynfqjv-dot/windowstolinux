/* Independently authored user-mode observations; no translator acceptance. */
#include <windows.h>
static void emit(char c) {
    DWORD count = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &c, 1, &count, 0) || count != 1)
        ExitProcess(90);
}
int main(int argc, char **argv) {
    char mode = argc == 2 ? argv[1][0] : '?';
    if (mode == 'n') {
        __try { emit('B'); } __finally { emit('F'); }
    } else if (mode == 'u') {
        __try {
            __try { emit('B'); RaiseException(0xe0420001, 0, 0, 0); emit('X'); }
            __finally { emit('F'); }
        } __except(EXCEPTION_EXECUTE_HANDLER) { emit('H'); }
    } else if (mode == 's') {
        __try {
            __try { emit('B'); RaiseException(0xe0420001, 0, 0, 0); }
            __except(EXCEPTION_CONTINUE_SEARCH) { emit('X'); }
        } __except(EXCEPTION_EXECUTE_HANDLER) { emit('H'); }
    } else if (mode == 'c') {
        __try { emit('B'); RaiseException(0xe0420001, 0, 0, 0); emit('C'); }
        __except(EXCEPTION_CONTINUE_EXECUTION) { emit('X'); }
    } else if (mode == 'e') {
        __try { emit('B'); ExitProcess(23); } __finally { emit('F'); }
    } else { return 91; }
    return 0;
}
