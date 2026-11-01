/* Authored instruction observations, MIT OR Apache-2.0. No PE translation.
 * Each block saves/restores its own full FP state before C formatting. */
#include <stdio.h>
#include <stdint.h>
#ifdef _MSC_VER
#define ALIGNED __declspec(align(16))
typedef char Pe32Only[(sizeof(void*)==4)?1:-1];
#else
#define ALIGNED __attribute__((aligned(16)))
#endif
static void observe(unsigned index, unsigned short input, unsigned mx) {
    ALIGNED unsigned char saved[512];
    unsigned short output=0, status=0; unsigned stored_mx=0;
#ifdef _MSC_VER
    __asm {
        fxsave saved
        fnclex
        fldcw input
        ldmxcsr mx
        fwait
        fnstcw output
        fnstsw status
        stmxcsr stored_mx
        fxrstor saved
    }
#else
    __asm__ volatile("fxsave64 %0; fnclex; fldcw %4; ldmxcsr %5; fwait; fnstcw %1; fnstsw %2; stmxcsr %3; fxrstor64 %0"
        : "+m"(saved),"=m"(output),"=m"(status),"=m"(stored_mx) : "m"(input),"m"(mx) : "memory");
#endif
    printf("{\"case\":%u,\"input\":%u,\"output\":%u,\"status_defined\":%u,\"mxcsr_in\":%u,\"mxcsr_out\":%u}\n",index,(unsigned)input,(unsigned)output,(unsigned)(status&0x80ff),mx,stored_mx);
}
int main(void) {
    static const unsigned short controls[]={0x003f,0x023f,0x033f,0x073f,0x0b3f,0x0f3f};
    unsigned i,j,n=0;
    setvbuf(stdout,NULL,_IONBF,0);
#ifdef _MSC_VER
    printf("{\"kind\":\"Windows PE32 FP instruction observations\",\"pointer_bytes\":%u,\"compiler\":%lu}\n",(unsigned)sizeof(void*),(unsigned long)_MSC_FULL_VER);
#else
    printf("{\"kind\":\"Linux native FP instruction observations\",\"pointer_bytes\":%u}\n",(unsigned)sizeof(void*));
#endif
    for(i=0;i<6;i++)for(j=0;j<2;j++)observe(n++,controls[i],0x1f80u|(j?0x603fu:0u));
    return n==12?0:1;
}
