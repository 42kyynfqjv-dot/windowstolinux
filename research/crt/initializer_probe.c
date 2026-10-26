/* Authored direct CRT API probe; MIT OR Apache-2.0. */
#include <stdio.h>
#include <stdlib.h>
typedef int (__cdecl *IntInit)(void);
typedef void (__cdecl *VoidInit)(void);
extern int __cdecl _initterm_e(IntInit *,IntInit *);
extern void __cdecl _initterm(VoidInit *,VoidInit *);
static int failing=0;
static int a(void){if(putchar('A')==EOF) exit(99);return failing?7:0;}
static int b(void){if(putchar('B')==EOF) exit(99);return 0;}
static void c(void){if(putchar('C')==EOF) exit(99);}
static void d(void){if(putchar('D')==EOF) exit(99);}
int main(int argc,char **argv){
 IntInit ints[]={NULL,a,NULL,b};VoidInit voids[]={NULL,c,d,NULL};int r;
 if(argc!=2) return 98;
 failing=argv[1][0]=='1';
 r=_initterm_e(ints,ints+4);if(r) return r;
 _initterm(voids,voids+4);return 0;
}
