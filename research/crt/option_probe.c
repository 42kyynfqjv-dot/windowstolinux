/* Independently authored x86 operation probe, MIT OR Apache-2.0.
 * Operates on local arrays, never executes code from the original PE. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
int main(int argc, char **argv) {
    uint32_t words[4]; unsigned char *bytes = (unsigned char *)words;
    uint32_t *first = words, *second = words + 2;
    uint32_t result_eax, result_ecx, result_flags, first_flags, second_flags;
    int i;
    if (argc != 2 || strlen(argv[1]) != 32) return 125;
    for (i = 0; i < 16; ++i) {
        int hi = nibble(argv[1][2*i]), lo = nibble(argv[1][2*i+1]);
        if (hi < 0 || lo < 0) return 125;
        bytes[i] = (unsigned char)(16*hi + lo);
    }
    __asm {
        mov eax, first
        mov ecx, [eax+4]
        or dword ptr [eax], 24h
        mov [eax+4], ecx
        pushfd
        pop first_flags
        mov eax, second
        mov ecx, [eax+4]
        or dword ptr [eax], 2
        mov [eax+4], ecx
        pushfd
        pop second_flags
        xor eax, eax
        mov result_eax, eax
        mov result_ecx, ecx
        pushfd
        pop result_flags
    }
    printf("{\"after\":\"");
    for (i = 0; i < 16; ++i) printf("%02x", (unsigned int)bytes[i]);
    printf("\",\"eax\":%u,\"ecx\":%u,\"eflags\":%u,\"helper_defined_flags\":[%u,%u]}\n", result_eax, result_ecx, result_flags, first_flags & 0x8c5u, second_flags & 0x8c5u);
    return 0;
}
