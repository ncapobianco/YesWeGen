typedef enum {false, true} bool;
double round(double);

int pushlen(int len){
	int r=5*((len-(len%4))/4);
	switch(len%4){
		case 1:
			r+=2;
			break;
		case 2:
			r+=5;
			break;
		case 3:
			r+=6;
			break;
		default:
			r+=1;
			break;
	}
	return r;
}
char* format_push (__u8 *shell, int *byte) {
	int i=0,l=1;
	char *ptr,n [30];
	switch (shell[0]) {
			case 0x6a:
				i+=2;
				l+=12;
				break;
			case 0x50:
				switch (shell[++i]) {
					case 0x66:
						i+=4;
						l+=26;
						break;
					case 0x68:
						i+=5;
						l+=29;
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
				i+=4;
				l+=15;
				break;
			case 0x68:
				i+=5;
				l+=18;
				break;
			default:
				break;
		}
	ptr=(char*) malloc(l);
	i=0;
	ptr[0]=0;
	switch (shell[i]) {
		case 0x6a:
			sprintf (n, "\tpush\t$0x%.02x\n",shell[i+1]); //asd 
			i+=2;
			break;
		case 0x50:
			switch (shell[++i]) {
				case 0x66:
					sprintf (n, "\tpush\t%%eax\n"
						    "\tpushw\t$0x%.02x%.02x\n", shell[i+3],shell[i+2]);
					i+=4;
					break;
				case 0x68:
					sprintf (n, "\tpush\t%%eax\n"
						    "\tpush\t$0x%.02x%.02x%.02x%.02x\n", shell[i+4],shell[i+3], shell[i+2],shell[i+1]);
					i+=5;
					break;
				default:
					break;
			}
		default:
			break;
	}
	strcat (ptr, n);
	while(shell[i]!=0x89) {
		switch (shell[i]) {
			case 0x66:
				sprintf (n,"\tpushw\t$0x%.02x%.02x\n", shell[i+3],shell[i+2]);
				i+=4;
				break;
			case 0x68:
				sprintf (n,"\tpush\t$0x%.02x%.02x%.02x%.02x\n", shell[i+4],shell[i+3], shell[i+2],shell[i+1]);
				i+=5;
				break;
			default:
				break;
		}
		strcat (ptr, n);
	}
	*byte = i;
	return ptr;
}

bool _random(){
	int fd = open("/dev/urandom", O_RDONLY);
	__u8 r;
	read(fd, &r, 1);
	close(fd);
	return (r>128) ? 1:0;
	
}

__u8 _rrand(int max,int min){
	int fd = open("/dev/urandom", O_RDONLY);
	__u8 r;
	double n;
	read(fd, &r, 1);
	close(fd);
	n=(((double)r/255)*(max-min))+min;
	return (__u8)round(n);
}
char *stdinr(){
	int flag, n, len=100, i=0;
	char tmp=0, *r=(char *)malloc(1*sizeof(char));
	struct pollfd pollo;
	pollo.fd=dup(0);
	pollo.events=POLLIN;
	if(!poll(&pollo, 1, 10)) return NULL;
	while(read(0,&tmp,1)>0){
		r=(char *)realloc(r, ++i);
		r[i-1]=tmp;
	}
	if(r[i-1]!=0x0a)
		r=(char *)realloc(r, ++i);
	r[i-1]=0x00;
	return r;
}
int is_hex (char ch) {
	int n = -1;
	if ((ch>='0')&&(ch<='9'))
		n=ch-'0';
	if ((ch>='a')&&(ch<='f'))
		n=ch-'a'+10;
	return n;
}

int is_shellcode (char *string) {
	int i,n;
	for (i=0;i<strlen(string);i+=4) {
		if ((strncmp (string+i, "\\x", 2)) || (is_hex (string[i+2])<0) || (is_hex (string[i+3])<0))
			return 0;
	}
	return 1;
}

int atox (char *str) {
	int i,l;
	unsigned int s=0;
	for(i=0,l=strlen(str)-1;is_hex(str[i])>=0;i++,l--)
		s+=is_hex(str[i])*(int)pow(16,l);
	return s;
}


__u8 *string2shellcode (char *string) {
	__u8 *shellcode = (__u8*) malloc (strlen(string)/4);
	char tmp [3];
	tmp [2] = 0x00;
	int i;
	for (i=0;i<strlen(string);i+=4) {
		tmp [0] = string [i+2];
		tmp [1] = string [i+3];
		shellcode [i/4] = (__u8) atox (tmp);
	}
	return shellcode;
}

int pushed_bytes(char *cmd, char *shcp){
	int l=26, len=strlen(cmd);
	if(!(len%2))
		l += len+4;
	else
		l+=len+3;
	len=strlen(shcp);
	if(!(len%2))
		l += len+4;
	else
		l+=len+3;
	return l;
}

