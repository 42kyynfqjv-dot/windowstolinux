/* Bounded, own-child, separately labelled instrumented observation.
 * Original PE/source files are never modified. INT3 bytes and temporary TF are
 * debugger instrumentation; this is NOT an ordinary Windows baseline run.
 * No privilege changes, unrelated process access, kernel or driver operations. */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_SITES 24
#define MAX_EVENTS 2048
#define MAX_HITS 256
#define MAX_CHAIN 12
#define FAIL() do { failure_line=__LINE__;last_error=GetLastError();goto cleanup; } while(0)
struct Site { DWORD rva, address, id; BYTE byte; BOOL patched; };
static struct Site sites[MAX_SITES];
static unsigned site_count;
static DWORD image_size, handler_rva, nested_rva, nlg_rva, rtl_iat_rva;
static BOOL read_exact(HANDLE p,DWORD at,void *out,SIZE_T n) {
    SIZE_T got=0;
    return (ULONGLONG)at+n<=0x100000000ULL && ReadProcessMemory(p,(void *)(uintptr_t)at,out,n,&got) && got==n;
}
static BOOL write_byte(HANDLE p,DWORD at,BYTE byte) {
    SIZE_T done=0;
    return WriteProcessMemory(p,(void *)(uintptr_t)at,&byte,1,&done) && done==1 && FlushInstructionCache(p,(void *)(uintptr_t)at,1);
}
static BOOL stack_read(HANDLE p,DWORD at,void *out,SIZE_T n,DWORD low,DWORD high) {
    return at>=low && (ULONGLONG)at+n<=high && read_exact(p,at,out,n);
}
static BOOL manifest(const char *path) {
    FILE *f=fopen(path,"r"); unsigned long a,b,c,d,e,id,rva,byte; char extra,line[128];
    if(!f)return FALSE;
    if(!fgets(line,sizeof(line),f) || !strchr(line,'\n') ||
       sscanf(line,"%lu %lu %lu %lu %lu %c",&a,&b,&c,&d,&e,&extra)!=5){fclose(f);return FALSE;}
    image_size=a;handler_rva=b;nested_rva=c;nlg_rva=d;rtl_iat_rva=e;
    if(image_size==0 || image_size>16*1024*1024 || handler_rva>=image_size || nested_rva>=image_size ||
       (ULONGLONG)nlg_rva+16>image_size || (ULONGLONG)rtl_iat_rva+4>image_size){fclose(f);return FALSE;}
    while(fgets(line,sizeof(line),f)) {
        if(!strchr(line,'\n') || sscanf(line,"%lu %lu %lu %c",&id,&rva,&byte,&extra)!=3){fclose(f);return FALSE;}
        if(site_count==MAX_SITES || id==0 || id>MAX_SITES || rva>=image_size || byte>255 || byte==0xcc){fclose(f);return FALSE;}
        for(unsigned i=0;i<site_count;i++)if(sites[i].id==id || sites[i].rva==rva){fclose(f);return FALSE;}
        sites[site_count].id=id;sites[site_count].rva=rva;sites[site_count].byte=(BYTE)byte;site_count++;
    }
    BOOL okay=site_count>0 && !ferror(f);
    fclose(f);return okay;
}
static BOOL module(HANDLE process,HANDLE file,DWORD base) {
    IMAGE_DOS_HEADER dos={0};IMAGE_NT_HEADERS32 nt={0};char path[2048]={0};
    if(!file || !read_exact(process,base,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE ||
       dos.e_lfanew<0 || dos.e_lfanew>4096 || !read_exact(process,base+(DWORD)dos.e_lfanew,&nt,sizeof(nt)) ||
       nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)return FALSE;
    DWORD n=GetFinalPathNameByHandleA(file,path,sizeof(path),FILE_NAME_NORMALIZED);
    if(n==0 || n>=sizeof(path))return FALSE;
    printf("{\"kind\":\"module\",\"base\":%lu,\"machine\":%u,\"timestamp\":%lu,\"size\":%lu,\"path_hex\":\"",
        base,nt.FileHeader.Machine,nt.FileHeader.TimeDateStamp,nt.OptionalHeader.SizeOfImage);
    for(DWORD k=0;k<n;k++)printf("%02x",(unsigned char)path[k]);
    puts("\"}");fflush(stdout);return TRUE;
}
static BOOL snapshot(HANDLE process,HANDLE thread,DWORD base,const struct Site *site,CONTEXT *c,unsigned sequence) {
    LDT_ENTRY selector={0};DWORD tib[3],nlg[4],rtl=0;
    if(!GetThreadSelectorEntry(thread,c->SegFs,&selector))return FALSE;
    DWORD teb=selector.BaseLow|((DWORD)selector.HighWord.Bytes.BaseMid<<16)|((DWORD)selector.HighWord.Bytes.BaseHi<<24);
    if(!read_exact(process,teb,tib,sizeof(tib)) || tib[2]>=tib[1] ||
       !read_exact(process,base+nlg_rva,nlg,sizeof(nlg)) || !read_exact(process,base+rtl_iat_rva,&rtl,4))return FALSE;
    struct Node {DWORD at,words[7],count;} nodes[MAX_CHAIN];unsigned count=0;DWORD cursor=tib[0];
    while(cursor!=0xffffffff) {
        if(count==MAX_CHAIN || cursor%4!=0)return FALSE;
        for(unsigned k=0;k<count;k++)if(nodes[k].at==cursor)return FALSE;
        struct Node *node=&nodes[count];node->at=cursor;node->count=2;
        if(!stack_read(process,cursor,node->words,8,tib[2],tib[1]))return FALSE;
        if(node->words[1]==base+handler_rva)node->count=4;
        if(node->words[1]==base+nested_rva)node->count=7;
        if(node->count>2 && !stack_read(process,cursor,node->words,node->count*4,tib[2],tib[1]))return FALSE;
        cursor=node->words[0];count++;
    }
    DWORD args[5]={0},record[4]={0};unsigned argc=0;
    if(site->id==1 || site->id==2 || site->id==16) {
        argc=5;
        if(!stack_read(process,c->Esp,args,sizeof(args),tib[2],tib[1]) ||
           !stack_read(process,args[1],record,sizeof(record),tib[2],tib[1]))return FALSE;
    } else if(site->id==3) {
        argc=4;
        if(!stack_read(process,c->Esp,args,16,tib[2],tib[1]))return FALSE;
    } else if(site->id==4 || site->id==17) {
        argc=4;
        if(!stack_read(process,c->Esp,args,16,tib[2],tib[1]))return FALSE;
    }
    printf("{\"kind\":\"site\",\"sequence\":%u,\"site\":%lu,\"rva\":%lu,\"image_base\":%lu,\"teb\":%lu,\"stack_limit\":%lu,\"stack_base\":%lu,\"fs_head\":%lu,",
        sequence,site->id,site->rva,base,teb,tib[2],tib[1],tib[0]);
    printf("\"eax\":%lu,\"ecx\":%lu,\"edx\":%lu,\"ebx\":%lu,\"esp\":%lu,\"ebp\":%lu,\"esi\":%lu,\"edi\":%lu,\"eflags\":%lu,\"rtl_address\":%lu,",
        c->Eax,c->Ecx,c->Edx,c->Ebx,c->Esp,c->Ebp,c->Esi,c->Edi,c->EFlags,rtl);
    printf("\"nlg\":[%lu,%lu,%lu,%lu],\"stack_words\":[",nlg[0],nlg[1],nlg[2],nlg[3]);
    for(unsigned k=0;k<argc;k++)printf("%s%lu",k?",":"",args[k]);
    printf("],\"record_prefix\":[");
    for(unsigned k=0;k<((site->id==1 || site->id==2 || site->id==16)?4u:0u);k++)printf("%s%lu",k?",":"",record[k]);
    printf("],\"chain\":[");
    for(unsigned k=0;k<count;k++) {
        printf("%s{\"address\":%lu,\"words\":[",k?",":"",nodes[k].at);
        for(unsigned j=0;j<nodes[k].count;j++)printf("%s%lu",j?",":"",nodes[k].words[j]);
        printf("]}");
    }
    puts("]}");fflush(stdout);return TRUE;
}
int main(int argc,char **argv) {
    STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};DEBUG_EVENT ev={0};
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE out=INVALID_HANDLE_VALUE,err=INVALID_HANDLE_VALUE,in=INVALID_HANDLE_VALUE;
    DWORD result=125,base=0,child_exit=0xffffffff,last_error=0;unsigned failure_line=0,events=0,hits=0,module_count=0;
    BOOL armed=FALSE,pending=FALSE,exited=FALSE,cleanup_ok=TRUE,success=FALSE;
    BOOL injected=argc==6 && strcmp(argv[5],"fail-after-first-hit")==0;int stepping=-1;
    ULONGLONG deadline=GetTickCount64()+20000;
    if(sizeof(void *)!=4 || (argc!=5 && !injected) || !manifest(argv[2]))return 125;
    out=CreateFileA(argv[3],GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    err=CreateFileA(argv[4],GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    in=CreateFileA("NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(out==INVALID_HANDLE_VALUE || err==INVALID_HANDLE_VALUE || in==INVALID_HANDLE_VALUE)FAIL();
    si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=out;si.hStdError=err;si.hStdInput=in;
    if(!CreateProcessA(argv[1],NULL,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi))FAIL();
    if(!DebugSetProcessKillOnExit(TRUE))FAIL(); /* watchdog termination also kills this owned debuggee */
    CloseHandle(out);out=INVALID_HANDLE_VALUE;CloseHandle(err);err=INVALID_HANDLE_VALUE;CloseHandle(in);in=INVALID_HANDLE_VALUE;
    while(events<MAX_EVENTS && GetTickCount64()<deadline) {
        if(!WaitForDebugEvent(&ev,100)){if(GetLastError()==ERROR_SEM_TIMEOUT)continue;FAIL();}
        pending=TRUE;events++;DWORD action=DBG_CONTINUE;
        if(ev.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) {
            base=(DWORD)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            BOOL valid=(ULONGLONG)base+image_size<=0x100000000ULL && module(pi.hProcess,ev.u.CreateProcessInfo.hFile,base);
            if(ev.u.CreateProcessInfo.hFile)CloseHandle(ev.u.CreateProcessInfo.hFile);
            if(!valid)FAIL();
        }else if(ev.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT) {
            BOOL valid=++module_count<=64 && module(pi.hProcess,ev.u.LoadDll.hFile,(DWORD)(uintptr_t)ev.u.LoadDll.lpBaseOfDll);
            if(ev.u.LoadDll.hFile)CloseHandle(ev.u.LoadDll.hFile);
            if(!valid)FAIL();
        }else if(ev.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT) {
            /* Debug-event thread handles are system-owned until continued EXIT_THREAD. */
            FAIL(); /* only frozen single-thread domain */
        }else if(ev.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
            child_exit=ev.u.ExitProcess.dwExitCode;exited=TRUE;
            if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE))FAIL();
            pending=FALSE;success=armed && hits>0 && stepping==-1 && child_exit==0;break;
        }else if(ev.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) {
            DWORD code=ev.u.Exception.ExceptionRecord.ExceptionCode;DWORD at=(DWORD)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            action=DBG_EXCEPTION_NOT_HANDLED;
            if(ev.dwThreadId!=pi.dwThreadId)FAIL();
            if(code==EXCEPTION_BREAKPOINT && !armed) {
                if(!base)FAIL();
                for(unsigned i=0;i<site_count;i++) {
                    BYTE actual=0;sites[i].address=base+sites[i].rva;
                    if(!read_exact(pi.hProcess,sites[i].address,&actual,1) || actual!=sites[i].byte)FAIL();
                    sites[i].patched=TRUE;
                    if(!write_byte(pi.hProcess,sites[i].address,0xcc))FAIL();
                }
                armed=TRUE;action=DBG_CONTINUE;
            }else if(code==EXCEPTION_BREAKPOINT && armed) {
                int found=-1;for(unsigned i=0;i<site_count;i++)if(sites[i].address==at)found=(int)i;
                if(found>=0) {
                    CONTEXT c={0};c.ContextFlags=CONTEXT_FULL;
                    if(stepping!=-1 || ++hits>MAX_HITS || !GetThreadContext(pi.hThread,&c) || c.Eip!=at+1 || (c.EFlags&0x100)!=0)FAIL();
                    c.Eip=at;
                    if(injected && hits==1)FAIL();
                    if(!snapshot(pi.hProcess,pi.hThread,base,&sites[found],&c,hits) || !write_byte(pi.hProcess,at,sites[found].byte))FAIL();
                    sites[found].patched=FALSE;c.EFlags|=0x100;
                    if(!SetThreadContext(pi.hThread,&c))FAIL();
                    stepping=found;action=DBG_CONTINUE;
                }else {
                    printf("{\"kind\":\"exception\",\"code\":%lu,\"address\":%lu,\"first_chance\":%lu}\n",code,at,ev.u.Exception.dwFirstChance);fflush(stdout);
                    /* Keep DBG_EXCEPTION_NOT_HANDLED for an unknown INT3. */
                }
            }else if(code==EXCEPTION_SINGLE_STEP && stepping>=0) {
                CONTEXT c={0};c.ContextFlags=CONTEXT_FULL;
                if(!GetThreadContext(pi.hThread,&c))FAIL();
                sites[stepping].patched=TRUE;
                if(!write_byte(pi.hProcess,sites[stepping].address,0xcc))FAIL();c.EFlags&=~0x100u;
                if(!SetThreadContext(pi.hThread,&c))FAIL();
                stepping=-1;action=DBG_CONTINUE;
            }else {
                printf("{\"kind\":\"exception\",\"code\":%lu,\"address\":%lu,\"first_chance\":%lu}\n",code,at,ev.u.Exception.dwFirstChance);fflush(stdout);
            }
        }
        if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,action))FAIL();
        pending=FALSE;
    }
cleanup:
    if(pi.hProcess && !exited) {
        for(unsigned i=0;i<site_count;i++)if(sites[i].patched && !write_byte(pi.hProcess,sites[i].address,sites[i].byte))cleanup_ok=FALSE;
        if(!TerminateProcess(pi.hProcess,125) && GetLastError()!=ERROR_ACCESS_DENIED)cleanup_ok=FALSE;
        if(pending) {if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE))cleanup_ok=FALSE;pending=FALSE;}
        ULONGLONG drain=GetTickCount64()+2000;
        while(GetTickCount64()<drain && !exited) {
            if(!WaitForDebugEvent(&ev,100))continue;
            if(ev.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile)CloseHandle(ev.u.LoadDll.hFile);
            if(ev.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile)CloseHandle(ev.u.CreateProcessInfo.hFile);
            /* CREATE_THREAD debug handles are closed by Windows on exit continuation. */
            if(ev.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){exited=TRUE;child_exit=ev.u.ExitProcess.dwExitCode;}
            if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE)){cleanup_ok=FALSE;break;}
        }
    }
    if(pi.hProcess && WaitForSingleObject(pi.hProcess,1000)!=WAIT_OBJECT_0)cleanup_ok=FALSE;
    if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);
    if(out!=INVALID_HANDLE_VALUE)CloseHandle(out);if(err!=INVALID_HANDLE_VALUE)CloseHandle(err);if(in!=INVALID_HANDLE_VALUE)CloseHandle(in);
    if(success && cleanup_ok && exited)result=0;
    printf("{\"kind\":\"summary\",\"success\":%s,\"cleanup_ok\":%s,\"child_exited\":%s,\"child_exit\":%lu,\"events\":%u,\"hits\":%u,\"failure_line\":%u,\"last_error\":%lu,\"instrumentation\":\"own-child INT3 and temporary TF; separate from baseline\"}\n",
        result==0?"true":"false",cleanup_ok?"true":"false",exited?"true":"false",child_exit,events,hits,failure_line,last_error);
    return (int)result;
}
