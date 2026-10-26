/* Independent authored probe, MIT OR Apache-2.0; never a translated fixture. */
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <string.h>
static char buffer[4096];
static void mark(char c) { FILE *f=NULL; if(fopen_s(&f,"markers","ab")) _exit(91); if(fputc(c,f)==EOF || fclose(f)) _exit(92); }
static void first(void){mark('A');}
static void second(void){mark('B');}
int main(int argc,char **argv){
 FILE *f=NULL;
 if(argc!=3) return 90;
 if(!strcmp(argv[1],"callbacks")) {
  if(fopen_s(&f,"markers","wb")) return 93;
  if(fclose(f) || atexit(first) || atexit(second)) return 94;
 } else if(!strcmp(argv[1],"buffer")) {
  if(setvbuf(stdout,buffer,_IOFBF,sizeof(buffer)) || fwrite("X",1,1,stdout)!=1) return 95;
 } else return 96;
 if(!strcmp(argv[2],"quick")) _exit(0);
 if(strcmp(argv[2],"normal")) return 97;
 exit(0);
}
