/* Independent observations of context restoration and nonlocal transfer.
 * Ordinary MSVC CRT entry. No translated execution or handler replacement. */
#include <windows.h>

static volatile LONG visits;
static volatile DWORD fault_ip;
static volatile LONG owned_value = 42;

static void emit(char c) {
    DWORD n = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &c, 1, &n, 0) || n != 1)
        ExitProcess(90);
}

/* Exact authored faulting instruction. The filter repairs EAX, then Windows
 * retries this instruction. No guessed instruction length or EIP increment. */
__declspec(naked) static LONG read_fault(void) {
    __asm {
        mov fault_ip, offset fault_instruction
        xor eax, eax
    fault_instruction:
        mov eax, dword ptr [eax]
        ret
    }
}

static LONG repair(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        p->ContextRecord->Eip != fault_ip || p->ContextRecord->Eax != 0 ||
        (p->ContextRecord->ContextFlags & CONTEXT_INTEGER) != CONTEXT_INTEGER ||
        InterlockedIncrement(&visits) != 1)
        ExitProcess(92);
    emit('V');
    p->ContextRecord->Eax = (DWORD)(ULONG_PTR)&owned_value;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG mutate(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode != 0xe0420011) ExitProcess(93);
    emit('I');
    p->ExceptionRecord->ExceptionCode = 0xe0420022;
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG select_mutated(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode != 0xe0420022) ExitProcess(94);
    emit('O');
    return EXCEPTION_EXECUTE_HANDLER;
}

__declspec(noinline) static void inner(void) {
    __try {
        __try { RaiseException(0xe0420011, 0, 0, 0); emit('X'); }
        __except(mutate(GetExceptionInformation())) { emit('Y'); }
    } __finally { emit('F'); }
    emit('Z');
}

int main(int argc, char **argv) {
    if (argc != 2) return 91;
    if (argv[1][0] == 'r') {
        LONG result = 0;
        __try { result = read_fault(); }
        __except(repair(GetExceptionInformation())) { return 95; }
        if (result != 42 || visits != 1) return 96;
        emit('R');
    } else if (argv[1][0] == 'u') {
        __try { inner(); emit('Q'); }
        __except(select_mutated(GetExceptionInformation())) { emit('H'); }
    } else return 91;
    return 0;
}
