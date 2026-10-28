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
#define MAX_SITES 20
#define MAX_EVENTS 2048
#define MAX_HITS 512
#define MAX_CHAIN 12
#define FAIL() do { failure_line=__LINE__;last_error=GetLastError();goto cleanup; } while(0)
struct Site { DWORD rva, address, id; BYTE byte; BOOL patched; };
static struct Site sites[MAX_SITES];
static unsigned site_count;
static DWORD image_size, stdout_rva, write_iat_rva;
static unsigned mode, write_calls;
static DWORD count_pointer, requested, write_arguments[5];
static BOOL saw_main, saw_stdout_flush, saw_stdout_unlock;
static BOOL write_word(HANDLE p,DWORD at,DWORD value) {
    SIZE_T done=0;
    return (ULONGLONG)at+4<=0x100000000ULL && WriteProcessMemory(p,(void *)(uintptr_t)at,&value,4,&done) && done==4;
}
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
    FILE *f=fopen(path,"r"); unsigned long a,b,c,id,rva,byte; char extra,line[128];
    if(!f)return FALSE;
    if(!fgets(line,sizeof(line),f) || !strchr(line,'\n') ||
       sscanf(line,"%lu %lu %lu %c",&a,&b,&c,&extra)!=3){fclose(f);return FALSE;}
    image_size=a;stdout_rva=b;write_iat_rva=c;
    if(image_size==0 || image_size>16*1024*1024 || (ULONGLONG)stdout_rva+56>image_size ||
       (ULONGLONG)write_iat_rva+4>image_size){fclose(f);return FALSE;}
    while(fgets(line,sizeof(line),f)) {
        if(!strchr(line,'\n') || sscanf(line,"%lu %lu %lu %c",&id,&rva,&byte,&extra)!=3){fclose(f);return FALSE;}
        if(site_count==MAX_SITES || id==0 || id>15 || rva>=image_size || byte>255 || byte==0xcc){fclose(f);return FALSE;}
        for(unsigned i=0;i<site_count;i++)if(sites[i].id==id || sites[i].rva==rva){fclose(f);return FALSE;}
        sites[site_count].id=id;sites[site_count].rva=rva;sites[site_count].byte=(BYTE)byte;site_count++;
    }
    BOOL okay=site_count==15 && !ferror(f);fclose(f);return okay;
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
    LDT_ENTRY selector={0};DWORD tib[3],stream[14],args[5]={0},triple[3]={0},count=0,iat=0;
    unsigned argc=0,triplen=0;BYTE buffer[8192];DWORD payload=0,stream_argument=0;
    if(!GetThreadSelectorEntry(thread,c->SegFs,&selector))return FALSE;
    DWORD teb=selector.BaseLow|((DWORD)selector.HighWord.Bytes.BaseMid<<16)|((DWORD)selector.HighWord.Bytes.BaseHi<<24);
    if(!read_exact(process,teb,tib,sizeof(tib)) || tib[2]>=tib[1] ||
       !read_exact(process,base+stdout_rva,stream,sizeof(stream)) || !read_exact(process,base+write_iat_rva,&iat,4))return FALSE;
    if(site->id==4) {
        argc=5;
        if(++write_calls>1 || !stack_read(process,c->Esp,args,20,tib[2],tib[1]) || args[4]!=0 ||
           args[2]==0 || args[2]>sizeof(buffer) || !stack_read(process,args[1],buffer,args[2],tib[2],tib[1]) ||
           !stack_read(process,args[3],&count,4,tib[2],tib[1]))return FALSE;
        memcpy(write_arguments,args,sizeof(args));count_pointer=args[3];requested=args[2];payload=args[2];
    }else if(site->id==5) {
        if(write_calls!=1 || !stack_read(process,count_pointer,&count,4,tib[2],tib[1]))return FALSE;
    }else if(site->id==6) {
        triplen=3;if(!stack_read(process,c->Eax,triple,12,tib[2],tib[1]))return FALSE;
    }else if(site->id==8 || site->id==9) {
        argc=2;if(!stack_read(process,c->Esp,args,8,tib[2],tib[1]))return FALSE;
        stream_argument=args[1];
        if(site->id==9 && stream_argument==base+stdout_rva && write_calls){saw_stdout_flush=TRUE;}
    }else if(site->id==10 || site->id==12) {
        argc=1;if(!stack_read(process,c->Esp,args,4,tib[2],tib[1]))return FALSE;
        stream_argument=args[0]-32;
    }else if(site->id==11 || site->id==13) {
        if(!stack_read(process,c->Ebp+8,&stream_argument,4,tib[2],tib[1]))return FALSE;
        if(site->id==13 && stream_argument==base+stdout_rva && saw_stdout_flush && stream[10]==0)saw_stdout_unlock=TRUE;
    }
    if(site->id==3)saw_main=TRUE;
    printf("{\"kind\":\"site\",\"sequence\":%u,\"site\":%lu,\"rva\":%lu,\"image_base\":%lu,\"stack_limit\":%lu,\"stack_base\":%lu,",sequence,site->id,site->rva,base,tib[2],tib[1]);
    printf("\"eax\":%lu,\"ecx\":%lu,\"edx\":%lu,\"ebx\":%lu,\"esp\":%lu,\"ebp\":%lu,\"esi\":%lu,\"edi\":%lu,\"eflags\":%lu,\"writefile_address\":%lu,",c->Eax,c->Ecx,c->Edx,c->Ebx,c->Esp,c->Ebp,c->Esi,c->Edi,c->EFlags,iat);
    printf("\"stdout_address\":%lu,\"stream_argument\":%lu,\"count_cell\":%lu,\"count_value\":%lu,\"write_calls\":%u,\"stream_words\":[",base+stdout_rva,stream_argument,count_pointer,count,write_calls);
    for(unsigned k=0;k<14;k++)printf("%s%lu",k?",":"",stream[k]);
    printf("],\"arguments\":[");for(unsigned k=0;k<argc;k++)printf("%s%lu",k?",":"",args[k]);
    printf("],\"text_result\":[");for(unsigned k=0;k<triplen;k++)printf("%s%lu",k?",":"",triple[k]);
    printf("],\"request_hex\":\"");for(DWORD k=0;k<payload;k++)printf("%02x",buffer[k]);puts("\"}");fflush(stdout);return TRUE;
}
int main(int argc,char **argv) {
    STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};DEBUG_EVENT ev={0};
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE out=INVALID_HANDLE_VALUE,err=INVALID_HANDLE_VALUE,in=INVALID_HANDLE_VALUE;
    DWORD result=125,base=0,child_exit=0xffffffff,last_error=0;unsigned failure_line=0,events=0,hits=0,module_count=0;
    BOOL armed=FALSE,pending=FALSE,exited=FALSE,cleanup_ok=TRUE,success=FALSE,interval_complete=FALSE;
    BOOL injected=argc==7 && strcmp(argv[6],"fail-after-first-hit")==0;int stepping=-1;
    if(argc>=6){if(strcmp(argv[5],"baseline")==0)mode=0;else if(strcmp(argv[5],"short-seven")==0)mode=1;
        else if(strcmp(argv[5],"short-one")==0)mode=2;else if(strcmp(argv[5],"zero-success")==0)mode=3;
        else if(strcmp(argv[5],"invalid-handle")==0)mode=4;else return 125;}
    ULONGLONG deadline=GetTickCount64()+20000;
    if(sizeof(void *)!=4 || (argc!=6 && !injected) || !manifest(argv[2]))return 125;
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
        if(ev.dwProcessId!=pi.dwProcessId)FAIL();
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
            /* No other thread context is read; an owned site on another thread rejects. */
            printf("{\"kind\":\"thread-created\",\"thread_id\":%lu}\n",ev.dwThreadId);fflush(stdout);
        }else if(ev.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
            child_exit=ev.u.ExitProcess.dwExitCode;exited=TRUE;
            if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE))FAIL();
            pending=FALSE;success=armed && interval_complete && hits>0 && stepping==-1 && child_exit==0;break;
        }else if(ev.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) {
            DWORD code=ev.u.Exception.ExceptionRecord.ExceptionCode;DWORD at=(DWORD)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            action=DBG_EXCEPTION_NOT_HANDLED;

            if(interval_complete) {
                printf("{\"kind\":\"exception\",\"code\":%lu,\"address\":%lu,\"first_chance\":%lu}\n",code,at,ev.u.Exception.dwFirstChance);fflush(stdout);
                /* Instrumentation is over: no other thread/context is touched. */
            }else if(code==EXCEPTION_BREAKPOINT && !armed) {
                if(!base || ev.dwThreadId!=pi.dwThreadId)FAIL();
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
                    if(ev.dwThreadId!=pi.dwThreadId || stepping!=-1 || ++hits>MAX_HITS || !GetThreadContext(pi.hThread,&c) || c.Eip!=at+1 || (c.EFlags&0x100)!=0)FAIL();
                    c.Eip=at;
                    if(injected && hits==1)FAIL();
                    if(!snapshot(pi.hProcess,pi.hThread,base,&sites[found],&c,hits))FAIL();
                    if(sites[found].id==4 && mode>=1 && mode<=3) {
                        DWORD value=mode==1?7:mode==2?1:0;
                        if(value>=requested || !write_word(pi.hProcess,count_pointer,value))FAIL();
                        c.Eax=1;c.Eip=at+6;c.Esp+=20;
                        if(!SetThreadContext(pi.hThread,&c))FAIL();
                        printf("{\"kind\":\"injection\",\"mode\":%u,\"count\":%lu,\"api_executed\":false,\"physical_bytes_written\":0}\n",mode,value);fflush(stdout);
                        action=DBG_CONTINUE;
                        if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,action))FAIL();pending=FALSE;continue;
                    }
                    if(sites[found].id==4 && mode==4) {
                        if(!write_word(pi.hProcess,c.Esp,0xffffffff))FAIL();
                        printf("{\"kind\":\"injection\",\"mode\":4,\"api_executed\":true,\"argument\":\"INVALID_HANDLE_VALUE\"}\n");fflush(stdout);
                    }
                    if(!write_byte(pi.hProcess,at,sites[found].byte))FAIL();
                    sites[found].patched=FALSE;c.EFlags|=0x100;
                    if(!SetThreadContext(pi.hThread,&c))FAIL();
                    stepping=found;action=DBG_CONTINUE;
                }else {
                    printf("{\"kind\":\"exception\",\"code\":%lu,\"address\":%lu,\"first_chance\":%lu}\n",code,at,ev.u.Exception.dwFirstChance);fflush(stdout);
                    /* Keep DBG_EXCEPTION_NOT_HANDLED for an unknown INT3. */
                }
            }else if(code==EXCEPTION_SINGLE_STEP && stepping>=0) {
                if(ev.dwThreadId!=pi.dwThreadId)FAIL();
                CONTEXT c={0};c.ContextFlags=CONTEXT_FULL;
                if(!GetThreadContext(pi.hThread,&c))FAIL();
                BOOL last=saw_main && saw_stdout_flush && saw_stdout_unlock;
                if(!last) {
                    sites[stepping].patched=TRUE;
                    if(!write_byte(pi.hProcess,sites[stepping].address,0xcc))FAIL();
                }
                c.EFlags&=~0x100u;
                if(!SetThreadContext(pi.hThread,&c))FAIL();
                if(last) {
                    for(unsigned i=0;i<site_count;i++)if(sites[i].patched) {
                        if(!write_byte(pi.hProcess,sites[i].address,sites[i].byte))FAIL();
                        sites[i].patched=FALSE;
                    }
                    interval_complete=TRUE;
                    printf("{\"kind\":\"interval-complete\",\"last_site\":%lu,\"hits\":%u,\"breakpoints_restored\":true,\"trap_flag_cleared\":true}\n",sites[stepping].id,hits);fflush(stdout);
                }
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
        for(unsigned i=0;i<site_count;i++)if(sites[i].patched) {
            if(!write_byte(pi.hProcess,sites[i].address,sites[i].byte))cleanup_ok=FALSE;
            else sites[i].patched=FALSE;
        }
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
    BOOL restored=TRUE;for(unsigned i=0;i<site_count;i++)if(sites[i].patched)restored=FALSE;
    if(success && cleanup_ok && exited && restored)result=0;
    printf("{\"kind\":\"summary\",\"success\":%s,\"cleanup_ok\":%s,\"child_exited\":%s,\"child_exit\":%lu,\"events\":%u,\"hits\":%u,\"failure_line\":%u,\"last_error\":%lu,\"interval_complete\":%s,\"breakpoints_restored\":%s,\"instrumentation\":\"own-child INT3 and temporary TF; scripted API results separately labelled; not ordinary baseline\"}\n",
        result==0?"true":"false",cleanup_ok?"true":"false",exited?"true":"false",child_exit,events,hits,failure_line,last_error,interval_complete?"true":"false",restored?"true":"false");
    return (int)result;
}
