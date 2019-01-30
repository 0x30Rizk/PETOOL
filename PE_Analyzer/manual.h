/*
	This is the manual file,which will list every single command of how to use the program
*/
void manual() {
	//ICON
	char* arr[9];
	int i = 0;
	arr[0] =(char*) " \n _______   ________        ________  ______    ______   __";
	arr[1] = (char*) "/       \\ /        |      /        |/      \\  /      \\ /  |";
	arr[2] = (char*) "$$$$$$$  |$$$$$$$$/       $$$$$$$$//$$$$$$  |/$$$$$$  |$$ |";
	arr[3] = (char*) "$$ |__$$ |$$ |__             $$ |  $$ |  $$ |$$ |  $$ |$$ |";
	arr[4] = (char*) "$$    $$/ $$    |            $$ |  $$ |  $$ |$$ |  $$ |$$ |";
	arr[5] = (char*) "$$$$$$$/  $$$$$/             $$ |  $$ |  $$ |$$ |  $$ |$$ |";
	arr[6] = (char*) "$$ |      $$ |_____          $$ |  $$ \\__$$ |$$ \__ $$ |$$ |_____";
	arr[7] = (char*) "$$ |      $$       |         $$ |  $$    $$/ $$    $$/ $$       |";
	arr[8] = (char*) "$$/       $$$$$$$$/          $$/    $$$$$$/   $$$$$$/  $$$$$$$$/";

	while (i<sizeof(arr) / sizeof(char*)) {	printf("%s\n", arr[i++]);}
	printf("\nShow Hex View\n==========================\n");
	printf("-view <filepath/filename>		//showing hex view of this file\n");
	printf("\nShow PE Headers\n========================\n");
	printf("-all <filepath/filename>		//showing all pe headers of this file\n");
	printf("-dos <filepath/filename>		//showing dos header of this file\n");
	printf("-nt  <filepath/filename>		//showing nt(file¡Boptional) header of this file\n");
	printf("-section <filepath/filename>	\t//showing section header of this file\n");
	
}

