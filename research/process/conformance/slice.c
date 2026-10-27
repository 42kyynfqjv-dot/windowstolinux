/* Independent custom-entry memory conformance: overlapping leftward byte copy.
 * MIT OR Apache-2.0. One synchronous read, at most 32 bytes, regular files. */
#include <windows.h>
DWORD WINAPI entry(void) {
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE), output=GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned char bytes[32]; DWORD n,i,sent,done;
    if (!input || input==INVALID_HANDLE_VALUE || !output || output==INVALID_HANDLE_VALUE) return 10;
    if (!ReadFile(input,bytes,32,&n,0)) return 11;
    if (n>32) return 14;
    if (!n) return 0;
    for(i=1;i<n;++i) bytes[i-1]=bytes[i];
    --n; sent=0;
    while(sent<n) {
        if (!WriteFile(output,bytes+sent,n-sent,&done,0)) return 12;
        if (!done || done>n-sent) return 13;
        sent+=done;
    }
    return 0;
}
