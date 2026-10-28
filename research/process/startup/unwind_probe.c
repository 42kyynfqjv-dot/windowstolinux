/* Independently authored SEH experiment, MIT OR Apache-2.0.
 * ScopeTable is OUR format, used by Dispatch. It is not MSVC EH4 metadata.
 * The naked Restore demonstration follows completed Windows SEH unwinding;
 * it observes only EAX/ESP/EBP/EIP, not all registers or Windows dispatch. */
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(_M_IX86)
#error This experiment requires the x86 Windows CONTEXT ABI.
#endif
typedef char check_eax[(offsetof(CONTEXT, Eax) == 176) ? 1 : -1];
typedef char check_ebp[(offsetof(CONTEXT, Ebp) == 180) ? 1 : -1];
typedef char check_eip[(offsetof(CONTEXT, Eip) == 184) ? 1 : -1];
typedef char check_esp[(offsetof(CONTEXT, Esp) == 196) ? 1 : -1];
typedef struct Cells { DWORD trace; DWORD local; } Cells;
typedef char check_cells[(sizeof(Cells) == 8) ? 1 : -1];
typedef void (__cdecl *Cleanup)(Cells *);
typedef struct Scope { LONG parent; Cleanup target; } Scope;
typedef char check_scope[(sizeof(Scope) == 8) ? 1 : -1];

__declspec(naked) void __cdecl CleanupA(Cells *cells) {
    __asm {
        mov ecx,[esp+4]
        mov eax,[ecx]
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,1
        mov [ecx],eax
        add dword ptr [ecx+4],7
        ret
    }
}
__declspec(naked) void __cdecl CleanupB(Cells *cells) {
    __asm {
        mov ecx,[esp+4]
        mov eax,[ecx]
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,2
        mov [ecx],eax
        add dword ptr [ecx+4],11
        ret
    }
}
__declspec(naked) void __cdecl CleanupC(Cells *cells) {
    __asm {
        mov ecx,[esp+4]
        mov eax,[ecx]
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,eax
        add eax,3
        mov [ecx],eax
        add dword ptr [ecx+4],13
        ret
    }
}
const Scope ScopeTable[3] = {{1, CleanupA}, {-1, CleanupB}, {-1, CleanupC}};
static volatile DWORD trace_value, inner_result, outer_result, abandoned;
static volatile LONG inner_cursor_result, outer_cursor_result;
static const DWORD exception_code = 0xe0424242;

__declspec(noinline) static void Dispatch(volatile LONG *cursor, volatile DWORD *local) {
    const volatile Scope *table = ScopeTable;
    LONG index = *cursor;
    Cells cells;
    if (index < 0 || index >= 3) ExitProcess(91);
    cells.trace = trace_value;
    cells.local = *local;
    table[index].target(&cells);
    trace_value = cells.trace;
    *local = cells.local;
    *cursor = table[index].parent;
}
__declspec(noinline) static void Inner(void) {
    volatile DWORD local = 100;
    volatile LONG cursor = 0;
    __try {
        __try {
            RaiseException(exception_code, 0, 0, NULL);
            abandoned |= 1;
        } __finally {
            Dispatch(&cursor, &local);
        }
        abandoned |= 2;
    } __finally {
        Dispatch(&cursor, &local);
        inner_result = local;
        inner_cursor_result = cursor;
    }
    abandoned |= 4;
}
__declspec(noinline) static void Outer(void) {
    volatile DWORD local = 200;
    volatile LONG cursor = 2;
    __try {
        Inner();
        abandoned |= 8;
    } __finally {
        Dispatch(&cursor, &local);
        outer_result = local;
        outer_cursor_result = cursor;
    }
    abandoned |= 16;
}
__declspec(naked) void __cdecl Restore(CONTEXT *saved) {
    __asm {
        mov ecx,[esp+4]
        mov eax,[ecx+176]
        mov esp,[ecx+196]
        mov ebp,[ecx+180]
        jmp dword ptr [ecx+184]
    }
}
int main(void) {
    volatile DWORD selected = 300, handled = 0;
    CONTEXT saved = {0};
    DWORD observed_eax = 0, observed_esp = 0, observed_ebp = 0;
    DWORD base = (DWORD)(uintptr_t)GetModuleHandleW(NULL);
    __try {
        Outer();
        abandoned |= 32;
    } __except (GetExceptionCode() == exception_code ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        handled = 1;
    }
    /* Same live main activation; snapshot before pushing Restore's argument.
     * Restore discards its call/argument words by restoring that exact ESP. */
    __asm {
        lea ecx,saved
        mov dword ptr [ecx+176],77
        mov [ecx+196],esp
        mov [ecx+180],ebp
        lea eax,restored
        mov [ecx+184],eax
        push ecx
        call Restore
        or abandoned,64
    restored:
        mov observed_eax,eax
        mov observed_esp,esp
        mov observed_ebp,ebp
    }
    printf("{\"table_rva\":%lu,\"cleanup_rvas\":[%lu,%lu,%lu],\"restore_rva\":%lu,\"restore_target_rva\":%lu,"
           "\"trace\":%lu,\"inner\":%lu,\"outer\":%lu,\"selected\":%lu,\"handled\":%lu,\"abandoned\":%lu,"
           "\"inner_cursor\":%ld,\"outer_cursor\":%ld,\"restore_eax\":%lu,\"restore_stack_equal\":%d,\"restore_frame_equal\":%d}\n",
           (DWORD)(uintptr_t)ScopeTable-base,
           (DWORD)(uintptr_t)CleanupA-base, (DWORD)(uintptr_t)CleanupB-base, (DWORD)(uintptr_t)CleanupC-base,
           (DWORD)(uintptr_t)Restore-base, saved.Eip-base,
           trace_value, inner_result, outer_result, selected, handled, abandoned,
           inner_cursor_result, outer_cursor_result, observed_eax, observed_esp == saved.Esp, observed_ebp == saved.Ebp);
    return trace_value == 0x123 && inner_result == 118 && outer_result == 213 && selected == 300 &&
           handled == 1 && abandoned == 0 && inner_cursor_result == -1 && outer_cursor_result == -1 &&
           observed_eax == 77 && observed_esp == saved.Esp && observed_ebp == saved.Ebp ? 0 : 1;
}
