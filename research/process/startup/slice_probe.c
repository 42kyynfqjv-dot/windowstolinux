/* Independently authored x86 handler: resume after a known two-byte UD2. */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
__declspec(naked) int __cdecl Handler(void *record,void *frame,CONTEXT *context,void *dispatcher) {
    __asm {
        mov ecx,[esp+12]
        add dword ptr [ecx+184],2
        mov dword ptr [ecx+176],42
        xor eax,eax
        ret
    }
}
int main(void) {
    DWORD result=0, fault_address=0;
    __asm {
        push offset Handler
        push dword ptr fs:[0]
        mov dword ptr fs:[0],esp
        lea eax,fault
        mov fault_address,eax
    fault:
        _emit 0x0f
        _emit 0x0b
        mov result,eax
        pop dword ptr fs:[0]
        add esp,4
    }
    CONTEXT c={0};
    c.Eax=10;c.Ecx=11;c.Edx=12;c.Ebx=13;c.Esp=0x8000;c.Ebp=0x8100;
    c.Esi=16;c.Edi=17;c.Eip=fault_address;c.EFlags=0x202;
    int disposition=Handler(NULL,NULL,&c,NULL);
    DWORD base=(DWORD)(uintptr_t)GetModuleHandleW(NULL);
    printf("{\"handler_rva\":%lu,\"fault_rva\":%lu,\"resume_rva\":%lu,\"actual_result\":%lu,\"disposition\":%d,\"context\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu]}",
        (DWORD)(uintptr_t)Handler-base,fault_address-base,c.Eip-base,result,disposition,
        c.Eax,c.Ecx,c.Edx,c.Ebx,c.Esp,c.Ebp,c.Esi,c.Edi,c.Eip-base,c.EFlags);
    return result==42 && disposition==0?0:1;
}
