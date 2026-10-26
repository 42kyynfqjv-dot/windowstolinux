/* Authored isolated CRT contract and scalar-conversion probes. MIT OR Apache-2.0.
 * Never calls original PE code; never inspects opaque onexit table members. */
#include <process.h>
#include <corecrt_startup.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
static int mark(char c) { return putchar(c)==EOF ? -1 : 0; }
static int a(void) { return mark('A'); }
static int b(void) { return mark('B'); }
static int c(void) { return mark('C'); }
static void x(void) { if (mark('X')) _exit(99); }
static void y(void) { if (mark('Y')) _exit(99); }
static void modules(void) {
    HMODULE list[]={GetModuleHandleA("ucrtbase.dll"),GetModuleHandleA("vcruntime140.dll")};
    unsigned int i;
    for(i=0;i<2;i++) {
        char path[32768]; DWORD n;
        if(!list[i]) continue;
        n=GetModuleFileNameA(list[i],path,sizeof(path));
        if(n && n<sizeof(path)) fprintf(stderr,"MODULE\t%lu\t%s\n",(unsigned long)(uintptr_t)list[i],path);
    }
}
static int scalar(void) {
    /* Fixed literal expectations are in Python, not computed by this instruction probe. */
    uint32_t pointers[]={1,0x80000000u,0xffffffffu,0,1,1};
    uint32_t results[]={0,0,0,0,1,0xffffffffu}; unsigned int i;
    for(i=0;i<6;i++) {
        uint32_t pointer=pointers[i], result=results[i], answer, flags;
        __asm {
            mov edx, pointer
            mov eax, result
            xor ecx, ecx
            test eax, eax
            cmove ecx, edx
            neg ecx
            sbb ecx, ecx
            neg ecx
            lea eax, [ecx-1]
            mov answer, eax
            pushfd
            pop flags
        }
        printf("%u %u\n",answer,flags & 0x8c5u);
    }
    return 0;
}
int main(int argc,char **argv) {
    _onexit_table_t first={0}, second={0};
    if(argc!=2) return 98;
    if(!strcmp(argv[1],"scalar")) return scalar();
    modules();
    if(!strcmp(argv[1],"process")) {
        /* Public atexit is separately labelled, not assumed equivalent to _crt_atexit. */
        if(atexit(x) || atexit(y)) return 97;
        return 0;
    }
    if(!strcmp(argv[1],"crt")) {
        if(_crt_atexit(x) || _crt_atexit(y)) return 97;
        return 0;
    }
    if(strcmp(argv[1],"tables")) return 98;
    if(_initialize_onexit_table(&first) || _initialize_onexit_table(&second)) return 91;
    if(_register_onexit_function(&first,a) || _register_onexit_function(&first,b)) return 92;
    if(_register_onexit_function(&second,c)) return 93;
    if(_execute_onexit_table(&first)) return 94;
    if(mark('|') || _execute_onexit_table(&second)) return 95;
    /* Consumed table is reinitialized before reuse, as required by Microsoft. */
    if(_initialize_onexit_table(&first) || _register_onexit_function(&first,c)) return 96;
    if(mark('|') || _execute_onexit_table(&first)) return 97;
    return 0;
}
