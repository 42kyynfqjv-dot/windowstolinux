/* Authored read-only installed-runtime measurement. MIT OR Apache-2.0. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
static int copy(const void *p, void *out, SIZE_T n) {
    SIZE_T done=0; return ReadProcessMemory(GetCurrentProcess(),p,out,n,&done) && done==n;
}
int main(int argc,char **argv) {
    HMODULE m=GetModuleHandleA("ucrtbase.dll"),owner;
    FARPROC target; IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS32 nt;
    IMAGE_SECTION_HEADER s; MEMORY_BASIC_INFORMATION region;
    DWORD base,rva,n=0,i,len; unsigned char bytes[4096];
    char path[32768],canonical[32768]; HANDLE file; FILE *out;
    if(argc!=2 || !m) return 90;
    target=GetProcAddress(m,"__p__commode");
    if(!target || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)target,&owner) || owner!=m) return 91;
    base=(DWORD)(uintptr_t)m;rva=(DWORD)(uintptr_t)target-base;
    if(!copy(m,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<0 || dos.e_lfanew>1048576) return 92;
    if(!copy((char*)m+dos.e_lfanew,&nt,sizeof(nt)) || nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC || nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER32) || nt.FileHeader.NumberOfSections>96 || rva>=nt.OptionalHeader.SizeOfImage) return 93;
    for(i=0;i<nt.FileHeader.NumberOfSections;++i) {
        if(!copy((char*)m+dos.e_lfanew+sizeof(nt)+i*sizeof(s),&s,sizeof(s)))return 94;
        if(rva>=s.VirtualAddress && rva-s.VirtualAddress<s.Misc.VirtualSize) {
            if(n || !(s.Characteristics&IMAGE_SCN_MEM_EXECUTE) || s.Characteristics&IMAGE_SCN_MEM_WRITE) return 95;
            n=s.Misc.VirtualSize-(rva-s.VirtualAddress);if(n>4096)n=4096;
        }
    }
    if(!n || VirtualQuery((void*)(uintptr_t)(base+rva),&region,sizeof(region))!=sizeof(region) || region.State!=MEM_COMMIT || region.Protect!=PAGE_EXECUTE_READ || region.AllocationBase!=m) return 96;
    if(n>region.RegionSize-((uintptr_t)target-(uintptr_t)region.BaseAddress)) n=(DWORD)(region.RegionSize-((uintptr_t)target-(uintptr_t)region.BaseAddress));
    if(!n || !copy((void*)(uintptr_t)(base+rva),bytes,n)) return 97;
    len=GetModuleFileNameA(m,path,sizeof(path));if(!len || len>=sizeof(path))return 98;
    file=CreateFileA(path,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(file==INVALID_HANDLE_VALUE)return 99;
    len=GetFinalPathNameByHandleA(file,canonical,sizeof(canonical),FILE_NAME_NORMALIZED);CloseHandle(file);if(!len || len>=sizeof(canonical))return 100;
    if(fopen_s(&out,argv[1],"wb"))return 101;
    if(fwrite(bytes,1,n,out)!=n){fclose(out);return 102;}fclose(out);
    printf("%lu %lu %lu %lu %u\n",(unsigned long)base,(unsigned long)rva,(unsigned long)n,(unsigned long)nt.OptionalHeader.SizeOfImage,nt.FileHeader.Machine);
    fprintf(stderr,"%s\n",canonical);return 0;
}
