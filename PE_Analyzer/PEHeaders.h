#define size_of_DOS_header 0x3E
#define size_of_FILE_header 0x18
#define size_of_OPTIONAL_header 0x60

/*Headers*/

struct IMAGE_DOS_HEADER {
	char* dos_arr[19] = 
	{
		(char*)"e_magic",(char*)"e_cblp",(char*)"e_cp",(char*)"e_crlc",
		(char*)"e_cparhdr",(char*)"e_minalloc",(char*)"e_maxalloc",	(char*)"e_ss",
		(char*)"e_sp",(char*)"e_csum",(char*)"e_ip",(char*)"e_cs",
		(char*)"e_lfarlc",(char*)"e_ovno",(char*)"e_res",(char*)"e_oemid",
		(char*)"e_oeminfo",(char*)"e_res2",(char*)"e_lfanew"
	};
};

struct IMAGE_NT_HEADER {
	char* file_arr[7] =
	{
		(char*)"Machine",(char*)"NumberOfSections",(char*)"TimeDateStamp",(char*)"PointerToSymbolTable",
		(char*)"NumberOfSymbols",(char*)"SizeOfOptionalHeader",(char*)"Characteristics"
	};
	char* Optional_arr[31] =
	{
	(char*)"Magic",(char*)"MajorLinkerVersion",(char*)"MinorLinkerVersion",(char*)"SizeOfCode",
	(char*)"SizeOfInitializedData",(char*)"SizeOfUninitializedData",(char*)"AddressOfEntryPoint",(char*)"BaseOfCode",
	(char*)"BaseOfData",(char*)"ImageBase",(char*)"SectionAlignment",(char*)"FileAlignment",
	(char*)"MajorOperatingSystemVersion",(char*)"MinorOperatingSystemVersion",(char*)"MajorImageVersion",(char*)"MinorImageVersion",
	(char*)"MajorSubsystemVersion",(char*)"MinorSubsystemVersion",(char*)"Win32VersionValue",(char*)"SizeOfImage",
	(char*)"SizeOfHeaders",(char*)"CheckSum",(char*)"Subsystem",(char*)"DllCharacteristics",
	(char*)"SizeOfStackReserve",(char*)"SizeOfStackCommit",(char*)"SizeOfHeapReserve",(char*)"SizeOfHeapCommit",
	(char*)"LoaderFlags",(char*)"NumberOfRvaAndSizes",(char*)"end"
	};
};

struct IMAGE_SECTION_HEADER
{
	char* section[10] = 
	{ 
		(char*)"Name",(char*)"Misc",(char*)"VirtualAddress",(char*)"SizeOfRawData",(char*)"PointerToRawData",
		(char*)"PointerToRelocations",(char*)"PointerToLinenumbers",(char*)"NumberOfRelocations",(char*)"NumberOfLinenumbers",
		(char*)"Characteristics"
	};
};

/*Explanation of each variables*/