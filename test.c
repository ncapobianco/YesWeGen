#include <stdio.h>	
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include "inutils.h"
#include "core.h"
#include "polymorphic.h"
#include "debug.h"


/*nota: powiamo il gen di black fino a 25 byte*/

/*buona scoperta: lo shellcode di black non è propriamente "null free", perchè ha bisogno di un null byte alla fine
cioè se dopo lo shellcode non c'è un byte nullo il codice non worka.
Funge quindi (ma potrebbe anche no!), nello stack, dove le variabili sono inizializzate tutte a \x00, e anche nelle variabili globali, ma se capita che nello stack no nsi trovi un byte nullo dopo lo shellcode quello di black va a soffriggere
e il nostro powa (per demonstration provare a gavare un byte di lunghezza dal debug.c)
powa ancora di più perchè è necessario un buffer ben 35 byte più corto!

comunque quello di black ottimizzato è in ./try/try.S (per sapere perchè serve vedere in todo)*/
int main(int argc, char *argv[]){
	int l,i,k;
	__u8 *shcode, *shellc;
	char *lol, ch;
	char options[10][12]={
		"--setuid",
		"--shellpath",
		"-a",
		"-r",
		"-p",
		"-n",
		"-s",
		"-c",
		"-j",		
		"--help"
		};
	bool setuid, a, r, p, help, code2read;
	setuid=false;
	a=false;
	r=false;
	p=false;
	help=false;
	code2read=false;
	int n=0, j=0;
	long long int s=0;
	char *shellpath=NULL, *code=NULL, *cmd, *shellcode;
	cmd = (char*) malloc (1);
	l=1;
	/*
	./gen [-setuid] command -l -asd <= shellcode normale (+ setuid iniziale facoltativo)
	./gen --shellpath /bin/bash command -l -asd <= shellcode normale + specifica shellpath
	./gen -a command -l -asd <= shellcode normale + print in asm
	./gen -r command -l -asd <= shellcode normale + print in raw
	./gen -p [-setuid DA IMPLEMENTARE] [-s Sub To ESP] -j jump command -l -sad <= shellcode polimorfico ascii printabile
	./gen -c code [-n NOP number] [-s Sub To ESP] <= converte shellcode passato come parametro in ascii printable
	*/
	for (i=1;i<argc;i++) {
		for (k=0;k<10;k++) { // Numero di options
			if (!strcmp (argv [i], options [k])) {
				switch (k) {
					case 0:
						setuid = true;
						break;
					case 1:
						if (i+1==argc) {
							printf ("Comando non specificato.\n");
							_exit (0);
							break;
						}
						shellpath = argv [++i];
						if ((shellpath [0] != '/') && (shellpath [0] != '.')) {
							printf ("!! Hai cercato di usare %s come shell, morirai per ciò.\n", shellpath);
							_exit (0);
						}
						break;
					case 2:
						a = true;
						break;
					case 3:
						r = true;
						break;
					case 4:
						p = true;
						break;
					case 5:
						if (i+1==argc) {
							printf ("Comando non specificato.\n");
							_exit (0);
						}
						n = atoi (argv [++i]);
						if (!n) {
							printf ("!! Parametro -n specificato senza un'argomento..\n");
							_exit (0);
						}
						break;
					case 6:
						if (i+1==argc) {
							printf ("Comando non specificato.\n");
							_exit (0);
						}
						s = atoll (argv [++i]);
						if (!s) {
							printf ("!! Parametro -s specificato senza un'argomento..\n");
							_exit (0);
						}
						break;
					case 7:
						if ((i+1==argc) || (argv [i+1] [0] == '-')) {
							if (!(code=stdinr()))
								code2read = true;
						}
						else
							code = argv [++i];
						break;
					case 8:
						if (i+1==argc) {
							printf ("Comando non specificato.\n");
							_exit (0);
						}
						j = atoi (argv [++i]);
						if (!j) {
							printf ("!! Parametro -j specificato senza un'argomento..\n");
							_exit (0);
						}
						break;
					case 9:
						help = true;
						break;
					default:
						break;
				}
				break;
			}
		}
		// Inizia il comando
		if (k==10) {
			for (;i<argc;i++) {
				l += strlen (argv [i])+(i!=argc-1);
				cmd = (char*) realloc (cmd, l);
				strcat (cmd, argv [i]);
				if (i!=argc-1)
					strcat (cmd, " ");
			}
		}
	}
	// Controlla che ci sia un comando o uno shellcode da convertire
	if ((!cmd[0]) && (!code) && (!code2read)) {
		printf ("Eh..?\n");
		_exit (0);
	}
	// Verifica se più di un parametro è stato passato
	if ((a) && (r)) {
		printf ("!! Hai specificato 2 parametri diversi di stampa; Verrà usato quello di default.\n");
		a = false;
		r = false;
	}
	// Verifica la presenza di parametri supplementari
	// In tal caso da un warning.
	if (((cmd [0]) && (!p) && (!code) && (!code2read)) && (s)) 
		printf ("!! Hai usato il parametro -s ove non richiesto. Verrà ignorato.\n");
	if ((!p) && (j)) 
		printf ("!! Hai usato il parametro -j ove non richiesto. Verrà ignorato.\n");
	if (((!code) && (!code2read)) && (n)) 
		printf ("!! Il parametro -n verrà usato solo nel caso di shellcode completamente polimorfico.\n");
	if (((code) || (code2read)) && (shellpath))
		printf ("!! Hai usato il parametro --shellpath ove non richiesto. Verrà ignorato.\n");
	
	// Verifica se mancano dei parametri
	// In tal caso li legge da input (solo se fondamentali)
	if ((p) && (!j)) {
		printf ("Hai dimenticato di specificare il parametro -j,\n"
			"che è fondamentale utilizzando -j.\n"
			"Inseriscilo ora (0 per generare uno shellcode completamente polimorfico).\n\n> ");
		scanf ("%d", &j);
	}
	if (code2read) {
		code = (char*)malloc(1);
		i = 0;
		printf ("Inserisci lo shellcode da convertire in polimorfico:\n"
			"Utilizza una sintassi come '\\x00\\xff\\x0a'\n");
		while ((ch=fgetc(stdin))!=0x0a) {
			code=(char*)realloc(code,++i);
			code [i-1]=ch;
		}
		code=(char*)realloc(code,++i);
		code[i-1]=0x00;
	}
	// Controlla che non siano per esempio usati parametri come
	// -p e -c insieme, oppure che venga specificato un comando insieme 
	// a -p e -c, in tal caso setta p e c a 0, in modo da generare lo 
	// shellcode sul comando passato.
	if ((p) && (code)) 
		printf ("Non è necessario specificare il parametro -p quando viene utilizzato -c.\n");
	if ((code) && (cmd [0])) {
		printf ("Hai specificato un comando e anche il parametro -c. Verrà ignorato il parametro -c.\n");
		code = NULL;
	}
	// Controlla, se è stato specificato uno shellcode da convertire, che
	// la sintassi utilizzata sia quella corretta, in caso affermativo
	// converte la stringa in __u8
	if (code) {
		if (!is_shellcode (code)) {
			printf ("Hai utilizzato una sintassi errata per lo shellcode.\n"
				"Ricorda che se lo passi da linea di comando devi\n"
				"Inserire il codice aggiungendo una \\ prima di tutte\n"
				"quelle presenti, in alternativa puoi racchiudere\n"
				"lo shellcode tra due \" \"\n"
				"Es. \\\\x00\\\\xff\\\\x0a oppure \"\\x00\\xff\\x0a\"\n");
			_exit (0);
		}
		shcode = string2shellcode (code);
	}
	if(p && !(code)){
		if(j)
			shellcode = polyasc_gen(cmd, shellpath, false/*setuid*/, s, j);
		else{
			shellc = shc_gen(cmd, (shellpath ? shellpath:DEF_PATH), setuid, &l);
			shellcode = shc2polyascprint(shellc, l, n, s);
		}
		printf("Lunghezza: %i\n", strlen(shellcode));
		printf("Byte pushati: %i\n", pushed_bytes(cmd, (shellpath ? shellpath:DEF_PATH)));
		printf("%s\n", shellcode);
	}else if(code && !cmd[0]){
		shellcode = shc2polyascprint(shcode, strlen(code)/4, n,s);
		printf("%s\n", shellcode);
	}else{
		shellc = shc_gen(cmd, (shellpath ? shellpath:DEF_PATH), setuid, &l);
		print_shellcode(shellc, l, (a ? __ASM__:r ? __RAW__:__HEX__));
		testc(cmd, DEF_PATH, 0,0,0);
	}
	free (cmd);
	return 0;
}
