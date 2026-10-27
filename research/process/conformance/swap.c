/* Independent custom-entry memory conformance: adjacent pair permutation.
 * MIT OR Apache-2.0. One synchronous read, at most 32 bytes, regular files. */
#include <windows.h>
DWORD WINAPI entry(void) {
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE), output=GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned char bytes[32],temporary; DWORD n,i,sent,done;
    if (!input || input==INVALID_HANDLE_VALUE || !output || output==INVALID_HANDLE_VALUE) return 10;
    if (!ReadFile(input,bytes,32,&n,0)) return 11;
    if (n>32) return 14;
    for(i=0;i+1<n;i+=2) {
        temporary=bytes[i]; bytes[i]=bytes[i+1]; bytes[i+1]=temporary;
    }
    sent=0;
    while(sent<n) {
        if (!WriteFile(output,bytes+sent,n-sent,&done,0)) return 12;
        if (!done || done>n-sent) return 13;
        sent+=done;
    }
    return 0;
}
