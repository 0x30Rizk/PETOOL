/*
Function:To detect special character from  Hex values
Parameters:Input hex for comparison
*/
char speChar(char hex) {
		int i = 0;
		char arr[] =
		{ 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
			,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E
			,0x1F,0x20,0x7F };

		while (i<sizeof(arr)) {
			if (hex == arr[i]) {
				return 0x00;
			}
			i++;
		}
		return hex;
}
/*
Functioin :Check Each Parameters from Pe is Zero or not
Parameter : char* arr---Address of file buffer
			int start--Pe starting point
		    int size--Size of parameter
*/
int CheckZero(unsigned char* arr, int start,int size) {
	int i = 0;
	unsigned int result = 0;
	arr = arr + start;
	while (i<size) {
		if (*arr != 0) {
			if (i == 0) {
				result += (unsigned char)(*arr);
			}
			else if (i == 1) {
				result += (unsigned char)(*arr) * 0x100;
			}
			else if (i == 2) {
				result += (unsigned char)(*arr) * 0x1000;
			}
			else {
				result += (unsigned char)(*arr) * 0x1000000;
			}
		}
		i++;
		arr++;
	}
	return result;
}
/*
Functioin : Dump the file hex
Parameter : Input filename 
*/
int HexDump(char* filename) {
		//Defining format	
		int* addr = (int*)0x00000000;
		printf("\t\t00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \n");
		printf("\t\t===============================================");
		printf("\n%p\t", addr);
		//Opening file
		FILE* pFile;
		int i = 0, j = 0;
		int file = fopen_s(&pFile, filename, "rb");
		//Calculation of file size
		fseek(pFile, 0, SEEK_END);
		int filesize = ftell(pFile);
		//Point the file pointer back to file original
		fseek(pFile, 0, SEEK_SET);
		//Create dynamic buffer in heap zone
		unsigned char* buf = (unsigned char*)malloc(sizeof(char)*filesize);
		memset(buf, 0, filesize);
		if (file == 0) {
			int read = fread_s(buf, sizeof(char)*filesize, filesize, 1, pFile);
			while (i <filesize) {//filesize
				if (j<16) {
					printf("%02x ", buf[i]);
					j++;
					i++;
				}
				else {
					j = i - 16;
					printf(" \t");
					while (j<i) {
						printf("%c ", speChar(buf[j]));
						j++;
					}
					j = 0;
					printf("\n%p\t", addr += 4);
				}

			}
		}
		else {
			fclose(pFile);
			return 0;
		}
		fclose(pFile);
		free(buf);
}
/*
Functions : Used to analyze PE file by printing DOS¡BNT¡BSection headers
Parameter : num=1--DOS header
			num=2--NT header
			num=3--Section header
*/
int Header(char* filename,int num) { 
	int i = 0, j = 0;
	//unsigned char e_lfname;
	unsigned int e_lfname = 0;
	//unsigned char NumberOfSections[2] = { 0 };
	unsigned short NumberOfSections = 0;
	unsigned short SizeOfOptionalHeader = 0;
	unsigned short StartSection = 0;
	
	//Opening file
	FILE* pFile;
	int file = fopen_s(&pFile, filename, "rb");
	fseek(pFile, 0, SEEK_END);		//Calculation of file size
	int filesize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);		//Point the file pointer back to file original
	//Create dynamic buffer in heap zone
	unsigned char* buf = (unsigned char*)malloc(sizeof(char)*filesize);
	memset(buf, 0, filesize);
	if (file == 0) {
		int read = fread_s(buf, sizeof(char)*filesize, filesize, 1, pFile);
		//Getting Information of e_lfname
		e_lfname = CheckZero((unsigned char*)buf,60,4);
		
		//Getting Information of NumberOfSections
		NumberOfSections = CheckZero((unsigned char*)buf, e_lfname+6, 2);
		
		//Getting Information of SizeOfOptionalHeader
		SizeOfOptionalHeader = CheckZero((unsigned char*)buf, e_lfname + 20, 2);

		//Section Header starting point
		StartSection = e_lfname + 24 + SizeOfOptionalHeader;

		//Distinguish PE File
		if (buf[0] != 0x4d & buf[1] != 0x5a) {
			printf("Not an execuable file!!\n");
			return 0;
		}
		else if (buf[e_lfname] != 0x50 & buf[e_lfname + 1] != 0x45) {
			printf("Not an PE structure!!\n");
			return 0;
		}

		//DOS headers
		if (num == 1) {
			struct IMAGE_DOS_HEADER DosHeader;

				while (i < size_of_DOS_header) {
					if (j < 14) {
						printf("%s == %02x %02x \n", DosHeader.dos_arr[j],buf[i + 1],buf[i]);
						j++;
						i += 2;
					}
					else if (j >= 14 & j < 18) {
						printf("%s[%d] == %02x %02x \n", DosHeader.dos_arr[14], (j- 14), buf[i + 1], buf[i]);
						j++;
						i += 2;
					}
					else if (j >= 18 & j < 20) {
						printf("%s == %02x %02x \n", DosHeader.dos_arr[j - 3], buf[i + 1], buf[i]);
						j++;
						i += 2;
					}
					else if (j >= 20 & j < 30) {
						printf("%s[%d] == %02x %02x \n", DosHeader.dos_arr[17], (j - 20), buf[i + 1], buf[i]);
						j++;
						i += 2;
					}
					else {
						printf("%s == %02x %02x %02x %02x \n", DosHeader.dos_arr[18], buf[i+3],buf[i+2],buf[i + 1], buf[i]);
						j++;
						i += 2;
					}
				}
			}
		//NT Headers(File¡BOptional)
		else if (num ==2) {			
			struct IMAGE_NT_HEADER NTHeader;
			printf("Signature == %02x %02x %02x %02x \n", buf[e_lfname + 3], buf[e_lfname + 2], buf[e_lfname + 1], buf[e_lfname]);
			printf("=========================\n");
			printf("FILE Headers\n=========================\n");
			i = e_lfname+4;	//FILE Headers Starting
			while (i<e_lfname+size_of_FILE_header)
			{
				if (i- e_lfname<8) {
					printf("%s == %02x %02x \n", NTHeader.file_arr[j], buf[i + 1], buf[i]);
					/*if (j==1 & buf[i + 1] == 0) {
						NumberOfSections[0] = buf[i];
					}
					else {
						NumberOfSections[0] = buf[i + 1];
						NumberOfSections[1] = buf[i];
					}*/
					j++;
					i += 2;
					
				}
				else if (i- e_lfname<20 & i- e_lfname >=8) {
					printf("%s == %02x %02x %02x %02x \n", NTHeader.file_arr[j], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
					j++;
					i += 4;
				}
				else {
					printf("%s == %02x %02x \n", NTHeader.file_arr[j], buf[i + 1], buf[i]);
					if (j == 5) {
						SizeOfOptionalHeader = buf[i];//F0--x64¡BE0--x86
					}
					j++;
					i += 2;
				}
			}
			j = 0;
			int init_optional = i; // the first value of optional header
			printf("=========================\n");
			printf("OPTIONAL Headers\n=========================\n");
			while (i<init_optional + SizeOfOptionalHeader -1) {
				if (i<init_optional + 0x3) {
					printf("%s == %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 1], buf[i]);
					i += 2;
					printf("%s == %02x \n", NTHeader.Optional_arr[j++], buf[i++]);
					printf("%s == %02x \n", NTHeader.Optional_arr[j++], buf[i++]);
				}
				else if (i< init_optional + 0x26 ) {
					printf("%s == %02x %02x %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
					i += 4;
				}
				else if(i < init_optional + 0x33){
					printf("%s == %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 1], buf[i]);
					i += 2;
				}
				else {
					if (i == init_optional + 0x44) { // WORD Subsystem¡BWORD DllCharacteristics;
						printf("%s == %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 1], buf[i]);
						i += 2;
						printf("%s == %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 1], buf[i]);
						i += 2;
					}
					else if (SizeOfOptionalHeader == 0xF0 & i< init_optional + 0x68 & i> init_optional + 0x46) { // For x64 system
						printf("%s == %02x%02x %02x%02x %02x%02x %02x%02x \n", NTHeader.Optional_arr[j++], buf[i + 7], buf[i + 6], buf[i + 5], buf[i + 4], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
						i += 8;
					}
					else {// For x32 system
						if (!strcmp("end", NTHeader.Optional_arr[j])) { break; }
						printf("%s == %02x %02x %02x %02x \n", NTHeader.Optional_arr[j++], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
						i += 4;
					}
				}
			}
		}
		//Section Headers
		else {
			struct IMAGE_SECTION_HEADER Section;
			unsigned char Name[9] = { 0 };
			i = StartSection; j = 0; int k = 0;
			printf("=========================\n");
			printf("SECTIONAL Headers\n=========================\n");
			while (i<StartSection+0x28* NumberOfSections) {
				if (j < 8) {
					printf("%s == %c%c%c%c%c%c%c%c\n", Section.section[k++], buf[i], buf[i+1], buf[i+2], buf[i + 3], buf[i+4],buf[i + 5],buf[i + 6],buf[i + 7]);
					i += 0x8;
					j = 8;
				}
				else if (j<0x20) {
					printf("%s == %02x %02x %02x %02x \n", Section.section[k++], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
					i += 4;
					j += 4;
				}
				else if(j<0x24){
					printf("%s == %02x %02x \n", Section.section[k++], buf[i + 1], buf[i]);
					i += 2;
					j += 2;
				}
				else {
					printf("%s == %02x %02x %02x %02x \n", Section.section[k++], buf[i + 3], buf[i + 2], buf[i + 1], buf[i]);
					printf("\n=========================\n");
					i += 4;
					j = 0;
					k = 0;
				}
			}
		}
	}
	else {
		fclose(pFile);
		return 0;
	}
	fclose(pFile);
	free(buf);
	return 0;
};

/*
Functions : Change ImageBuffer to FileBuffer
*/


/*
Functions :RVA2FOA
*/

/*
Functions :Shellcode Injection
*/