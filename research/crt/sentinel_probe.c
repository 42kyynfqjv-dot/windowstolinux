/* Independently authored CPU local-state probe. MIT OR Apache-2.0.
 * No original image code or imported initialization/registration is executed. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned char initialized;
static uint32_t mode_word;
static uint32_t tables[6];
__declspec(naked) static void query(void) {
    __asm {
        xor eax, eax
        cmp mode_word, eax
        setne al
        ret
    }
}
__declspec(naked) static void local_effect(void) {
    __asm {
        push ebp
        mov ebp, esp
        cmp initialized, 0
        je initialize
        mov al, 1
        pop ebp
        ret
    initialize:
        push esi
        mov esi, [ebp+8]
        call query
        test eax, eax
        jz stores
        test esi, esi
    stores:
        mov dword ptr tables[0], 0ffffffffh
        mov dword ptr tables[4], 0ffffffffh
        mov dword ptr tables[8], 0ffffffffh
        mov dword ptr tables[12], 0ffffffffh
        mov dword ptr tables[16], 0ffffffffh
        mov dword ptr tables[20], 0ffffffffh
        mov initialized, 1
        mov al, 1
        pop esi
        pop ebp
        ret
    }
}
int main(int argc,char **argv) {
    uint32_t policy, incoming, answer, flags, saved_esi, saved_ecx, saved_edx;
    uint32_t before_sp, after_sp, before_bp, after_bp; unsigned int i, value;
    unsigned char *bytes=(unsigned char *)tables;
    if(argc!=6 || strlen(argv[5])!=48) return 98;
    initialized=(unsigned char)strtoul(argv[1],NULL,10);
    mode_word=(uint32_t)strtoul(argv[2],NULL,10);
    policy=(uint32_t)strtoul(argv[3],NULL,10);
    incoming=(uint32_t)strtoul(argv[4],NULL,10);
    /* Only the independently scoped local path, never unknown foreign calls. */
    if(!initialized && policy!=1) return 97;
    for(i=0;i<24;i++){if(sscanf_s(argv[5]+2*i,"%2x",&value)!=1)return 96;bytes[i]=(unsigned char)value;}
    __asm {
        mov before_bp, ebp
        mov esi, 11223344h
        mov ecx, 12345678h
        mov edx, 87654321h
        mov eax, incoming
        push policy
        mov before_sp, esp
        call local_effect
        mov answer, eax
        pushfd
        pop flags
        mov after_sp, esp
        mov after_bp, ebp
        mov saved_esi, esi
        mov saved_ecx, ecx
        mov saved_edx, edx
        add esp, 4
    }
    if(before_sp!=after_sp || before_bp!=after_bp || saved_esi!=0x11223344u || saved_ecx!=0x12345678u || saved_edx!=0x87654321u) return 95;
    printf("{\"tables_after\":\"");
    for(i=0;i<24;i++)printf("%02x",bytes[i]);
    printf("\",\"flag_after\":%u,\"eax\":%u,\"defined_flags\":%u,\"af_bit\":%u,\"preserved_context\":true}\n",(unsigned int)initialized,answer,flags&0x8c5u,(flags>>4)&1u);
    return 0;
}
