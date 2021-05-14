// # pttb - Pin To TaskBar
// Usage:
//	> pttb Path\to\.exe\or\.lnk\to\PinToTaskbar
//	> pttb -u Path\to\.exe\or\.lnk\to\UnPinFromTaskBar
//	> pttb -r (to refresh the taskbar after modifying HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband)

// #include <windows.h>
#include <Shldisp.h>
#include <stdint.h>
// #include <stdio.h>

// --------------------------- Variables Definition --------------------------- //
#define NB_ARG				  2
#define REFRESH_TASKBAR		  0
#define DEFAULT_PIN			  1
#define ONLY_UNPIN			  2
#define DOS_HEAD_E_LFANEW	 60													// IMAGE_DOS_HEADER->e_lfanew: File address of new exe header
#define OPT_HEAD_IMG_SIZE	 80											 		// IMAGE_OPTIONAL_HEADER->SizeOfImage
#define RELOC_TBL_ADR		176												 	// IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->Base relocation table address
#define RELOC_TBL_SIZE		180												 	// IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->Base relocation table size
// -------------------------- Structures Definition --------------------------- //
struct locVirtAlloc_stc {	// Local Virtual Allocation Structure 
	void* locVirtAlloc_vp;
	long long moduleAdr_ll;
	long long imgHeadAdr_ll;
	unsigned long imgSize_ul;
};
struct remVirtAlloc_stc {	// Remote Virtual Allocation Structure 
	void* process_vp;
	void* remVirtAlloc_vp;
	long long relocOffset_ll;
};
// ----------------------- Program Functions Prototype ------------------------ //
void CommandLineToArgvA(char* cmdLine_cp, char** args_cpa);						// Get arguments from command line.. just a personal preference for char* instead of the wchar_t* type provided by "CommandLineToArgvW()"
void WriteToConsoleA(char* msg_cp);												// "Write to Console A" function to save >20KB compared to printf and <stdio.h>
char NoArgPassed(char* args_cp);
char CheckOption(char* args_cpa);
char FileNotFound(char* argPath_cp, char argPath_ca[]);


struct locVirtAlloc_stc SetLocVirtAlloc();
struct remVirtAlloc_stc SetRemVirtAlloc(struct locVirtAlloc_stc* locVirtAlloc);
void* GetProgmanProcess();
long long RelocVirtualAddress(struct locVirtAlloc_stc* locVirtAlloc, long long remVirtAllocAdr_ll);
void PEInject(char argPath_ca[], char* option_p, struct locVirtAlloc_stc* locVirtAlloc, struct remVirtAlloc_stc* remVirtAlloc);

static unsigned long __stdcall PinToTaskBar_func(char* pdata);					// "Pin to tas&kbar" Function to call once injected in "Progman"
char* SeparateDirFile(char* data_cp);
void GetPinVerbs(char option_c, wchar_t pttbVerb_wca[], wchar_t upftbVerb_wca[], wchar_t* pinVerbs[]);
void CheckPinnedShorcut(char* file_cp, wchar_t* pinVerbs[], IShellDispatch* ISD_p);
void PinToTaskBar_core(char* dir_cp, char* file_cp, wchar_t* pinVerbs[], IShellDispatch* ISD_p);  // Core Function of "PinToTaskBar_func"
void ExecuteVerb(wchar_t* verb_wcp, FolderItem* folderItem_p);					// Execute Verb if found
// void WriteHexToConsoleA(int num_i);											// "Write Integer as Hex to Console A" function to save >20KB compared to printf and <stdio.h>
// void WriteToConsoleW(wchar_t* msg_cp);										// "Write to Console W" function to save >20KB compared to printf and <stdio.h>
// -------------------------- C Functions Prototype --------------------------- //
int access(const char* path, int mode);											// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess?view=msvc-160
int sprintf(char* buffer, const char* format, ...);								// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-160

// ----------------------------- Global Variables ----------------------------- //
void* __stdcall consOut_vp;
// printf("\n FileNotFound: %s", argPath_ca);
// ExitProcess(0);

// --------------------------- entry point function --------------------------- //
void pttb() {
	consOut_vp = GetStdHandle(STD_OUTPUT_HANDLE);
// Get arguments from command line
	char* args_cpa[NB_ARG+1] = {NULL};											// 1st "argument" isnt really one: it's this program path
	char* cmdLine_cp = GetCommandLineA();
	CommandLineToArgvA(cmdLine_cp, args_cpa);									// Get arguments from command line
// Check arguments
	if(NoArgPassed(args_cpa[1])) {
		ExitProcess(ERROR_BAD_ARGUMENTS); }
	char option_c = CheckOption(args_cpa[1]);
	char* argPath_cp = args_cpa[option_c];
	if (!option_c && stricmp((char*)(argPath_cp+strlen(argPath_cp)-4),".exe")) {
		strcat(argPath_cp, ".exe"); }
	char argPath_ca[MAX_PATH];													// Full file path
	if (FileNotFound(argPath_cp, argPath_ca)) {
		ExitProcess(ERROR_FILE_NOT_FOUND); }
// Set Local/remote Virtual Allocation and PE inject
	struct locVirtAlloc_stc locVirtAlloc = SetLocVirtAlloc();
	struct remVirtAlloc_stc remVirtAlloc = SetRemVirtAlloc(&locVirtAlloc);
	PEInject(argPath_ca, &option_c, &locVirtAlloc, &remVirtAlloc);
// Clean Up
	VirtualFree(locVirtAlloc.locVirtAlloc_vp, 0, MEM_RELEASE);
	VirtualFreeEx(remVirtAlloc.process_vp, remVirtAlloc.remVirtAlloc_vp, 0, MEM_RELEASE);
	CloseHandle(remVirtAlloc.process_vp);
	ExitProcess(0);
}

// --------------------- Check if an Argument was passed ---------------------- //
char NoArgPassed(char* args_cp) {
	if(!args_cp) {
		WriteToConsoleA("\nERROR_BAD_ARGUMENTS: Arguments missing\n\nUsage:\n");
		WriteToConsoleA("To Pin / Force Re-Pin: > pttb Path\\to\\.exe\\or\\.lnk\\to\\PinToTaskBar\n");
		WriteToConsoleA("To UnPin Only:         > pttb -u Path\\to\\.exe\\or\\.lnk\\to\\UnPinFromTaskBar\n");
		WriteToConsoleA("To Refresh TaskBar:    > pttb -r\n");
		return TRUE; }
	return FALSE;
}

// ---------------------- check if an option was passed ----------------------- //
char CheckOption (char* args_cpa) {
	switch (*(short*)args_cpa) {
		case 0x752D:															// 0x752D: u-
		case 0x552D:															// 0x552D: U-
			return 2;
		case 0x722D:															// 0x722D: r-
		case 0x522D:															// 0x522D: R-
			return 0;
		default:
            return 1; }
}

// -------------------- Check if file to pin/unpin exists --------------------- //
char FileNotFound(char* argPath_cp, char argPath_ca[]) {
	if(access(argPath_cp, 0) < 0 ) {
		WriteToConsoleA("\nERROR_FILE_NOT_FOUND: \""); WriteToConsoleA(argPath_cp); WriteToConsoleA("\"\n");
		return TRUE; }
	GetFullPathNameA(argPath_cp, MAX_PATH, argPath_ca, NULL);
	return FALSE;
}

// ---------------------- Allocate local virtual memory ----------------------- //
struct locVirtAlloc_stc SetLocVirtAlloc() {
	struct locVirtAlloc_stc locVirtAlloc;
// Get relevant addresses to this current process, as well as the image size
	void* module_vp = GetModuleHandleA(NULL);		
	locVirtAlloc.moduleAdr_ll = (long long)module_vp;
	locVirtAlloc.imgHeadAdr_ll = locVirtAlloc.moduleAdr_ll + *(int*)(locVirtAlloc.moduleAdr_ll + DOS_HEAD_E_LFANEW); // E_LFANEW: File address of new exe header
	locVirtAlloc.imgSize_ul = *(unsigned long*)(locVirtAlloc.imgHeadAdr_ll + OPT_HEAD_IMG_SIZE); // 0x50: IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->SizeOfImage (Size of current process in memory)
// Reserve a local region of memory equal to "imgSize_ul" and make a copy of itself into it
	locVirtAlloc.locVirtAlloc_vp = VirtualAlloc(NULL, locVirtAlloc.imgSize_ul, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(locVirtAlloc.locVirtAlloc_vp, module_vp, locVirtAlloc.imgSize_ul);
	return locVirtAlloc;
}

// ---------------------- Allocate remote virtual memory ---------------------- //
struct remVirtAlloc_stc SetRemVirtAlloc(struct locVirtAlloc_stc* locVirtAlloc) {
	struct remVirtAlloc_stc remVirtAlloc;
	remVirtAlloc.process_vp = GetProgmanProcess();
	remVirtAlloc.remVirtAlloc_vp = VirtualAllocEx(remVirtAlloc.process_vp, NULL, locVirtAlloc->imgSize_ul+MAX_PATH+sizeof(char), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	remVirtAlloc.relocOffset_ll = RelocVirtualAddress(locVirtAlloc, (long long)(remVirtAlloc.remVirtAlloc_vp));
	return remVirtAlloc;
}

// --------------------------- Open Progman process --------------------------- //
void* GetProgmanProcess() {
	unsigned long procId_ul;
	GetWindowThreadProcessId(FindWindowA("Progman", NULL), &procId_ul);
	return OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, 0, procId_ul);
}

// ----------------------- Relocate virtual address --------------------------- //
long long RelocVirtualAddress(struct locVirtAlloc_stc* locVirtAlloc, long long remVirtAllocAdr_ll) {
	long long relocTblAdr_ll = (*(int*)(locVirtAlloc->imgHeadAdr_ll + RELOC_TBL_SIZE)) ? *(int*)(locVirtAlloc->imgHeadAdr_ll + RELOC_TBL_ADR) : 0; // 176/180: IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->Base relocation table address/size
	long long locVirtRelocTblAdr_ll = (long long)locVirtAlloc->locVirtAlloc_vp + relocTblAdr_ll;		// Address of the Relocation Table
	long long relocOffset_ll = remVirtAllocAdr_ll - locVirtAlloc->moduleAdr_ll;				// Relocation Offset between the current process and the reserved memory region in the "Progman" process
// Relocate every block of virtual address
	while (relocTblAdr_ll != 0) {
		int	relocBlokSize_i = *(int*)(locVirtRelocTblAdr_ll + 4);				// Block size to relocate from Virtual Address (size of struct _IMAGE_BASE_RELOCATION included)
		relocTblAdr_ll = (long long)locVirtAlloc->locVirtAlloc_vp + *(int*)locVirtRelocTblAdr_ll;		// Virtual Address relocation offset according ImageBase
		locVirtRelocTblAdr_ll += 8;												// 8: size of struct _IMAGE_BASE_RELOCATION // jump to 1st Descriptor to relocate
		if (relocBlokSize_i >= 8) {												// Block size must be > size of struct _IMAGE_BASE_RELOCATION in order to have any Descriptor
			int	relocNbDesc_i = (relocBlokSize_i - 8) / 2;						// number of descriptors in this block: relocBlokSize_i in BYTE, but descriptors in short
			for (int ct=0; ct<relocNbDesc_i; ct++) {
				short relocDescOffset_s = *(short*)locVirtRelocTblAdr_ll & 0x0FFF; // Get descriptor offset of Virtual address to relocate
				if (relocDescOffset_s != 0) { *(long long*)(relocTblAdr_ll + relocDescOffset_s) += relocOffset_ll; }  // Add "relocOffset_ll" to the value at this address
				locVirtRelocTblAdr_ll += 2; } }									// Go to next descriptor
		relocTblAdr_ll = *(int*)locVirtRelocTblAdr_ll; }						// Get Virtual Address of next Block
	return relocOffset_ll;
}

// --------------------------- PE Injection function -------------------------- //
void PEInject (char argPath_ca[], char* option_p, struct locVirtAlloc_stc* locVirtAlloc, struct remVirtAlloc_stc* remVirtAlloc) {
// Inject local region of memory into "Progman" process region of memory
	WriteProcessMemory(remVirtAlloc->process_vp, remVirtAlloc->remVirtAlloc_vp, locVirtAlloc->locVirtAlloc_vp, locVirtAlloc->imgSize_ul, NULL);
	void* cmdBase_vp = (void*)((long long)(remVirtAlloc->remVirtAlloc_vp) + locVirtAlloc->imgSize_ul);
	WriteProcessMemory(remVirtAlloc->process_vp, cmdBase_vp, argPath_ca, MAX_PATH, NULL);	// Copy the path to the file to pin to taskbar, into the extra memory of size "MAX_PATH"
	WriteProcessMemory(remVirtAlloc->process_vp, cmdBase_vp+MAX_PATH, option_p, sizeof(char), NULL);	// Copy the path to the file to pin to taskbar, into the extra memory of size "MAX_PATH"
// Run the "PinToTaskBar_func" in the "Progman" process, with the path to the file to pin to taskbar as a parameter
	LPTHREAD_START_ROUTINE startRoutine_lptsr = (LPTHREAD_START_ROUTINE)(remVirtAlloc->relocOffset_ll + PinToTaskBar_func);
	void* thread_vp = CreateRemoteThread(remVirtAlloc->process_vp, NULL, 0, startRoutine_lptsr, cmdBase_vp, 0, NULL);
// Wait for the Thread to finish and clean it up
	WaitForSingleObject(thread_vp, 10000);
	TerminateThread(thread_vp, 0);
	CloseHandle(thread_vp);
}

// ---------------------------- "Pin to tas&kbar" ----------------------------- //
// Note: Function to call once injected in "Progman"
static unsigned long __stdcall PinToTaskBar_func(char* data_cp) {
	char option_c = *(data_cp+MAX_PATH);
// Get directory and Filename from pdata
	char* dir_cp = data_cp;
	char* file_cp = SeparateDirFile(data_cp);
// Get Pin to taskbar and Unpin from taskbar Verbs
	wchar_t pttbVerb_wca[MAX_PATH];
	wchar_t upftbVerb_wca[MAX_PATH];
	wchar_t* pinVerbs[2] = {NULL};
	GetPinVerbs(option_c, pttbVerb_wca, upftbVerb_wca, pinVerbs);
// Create COM Objects
	CoInitialize(NULL);
	IShellDispatch* ISD_p;
	CoCreateInstance(&CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, &IID_IShellDispatch, (void**)&ISD_p);
// Check if Shorcut is already pinned, and if so: unpin it directly from %AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\shorcut.lnk, because Windows föks up when Unpinning shorcuts whose target/arguments have been modified after getting pinned..
	if (option_c) {
		CheckPinnedShorcut(file_cp, pinVerbs, ISD_p); }
	if (pinVerbs[0]) {
		PinToTaskBar_core(dir_cp, file_cp, pinVerbs, ISD_p); }
// Clean Up
	ISD_p->lpVtbl->Release(ISD_p);
	CoUninitialize();
	// MessageBox(NULL, "Check the TaskBar", "Done", 0);
	return 0;
}

// ----------------------- Separate file name from path ----------------------- //
char* SeparateDirFile(char* data_cp) {
	char* file_cp = NULL;
	while (*data_cp) {
		if(*data_cp == '\\') file_cp = data_cp;
		data_cp++; }
	*file_cp = 0;
	return file_cp+1;	
}

// ---------------------- Get Pin/Unpin Verbs in locale ----------------------- //
void GetPinVerbs(char option_c, wchar_t pttbVerb_wca[], wchar_t upftbVerb_wca[], wchar_t* pinVerbs[]) {
	void* shell32_vp = LoadLibraryW(L"shell32.dll");
	LoadStringW(GetModuleHandleW(L"shell32.dll"), 5387, upftbVerb_wca, MAX_PATH);	// 5387: "Unpin from tas&kbar" in en-us locale versions of Windows
	
	if (option_c != ONLY_UNPIN) {
		LoadStringW(GetModuleHandleW(L"shell32.dll"), 5386, pttbVerb_wca, MAX_PATH); } // 5386: "Pin to tas&kbar" in en-us locale versions of Windows
	else {
		pttbVerb_wca = NULL; }
	FreeLibrary(shell32_vp);
	
	if (option_c == REFRESH_TASKBAR) {
		pinVerbs[0] = pttbVerb_wca;
		pinVerbs[1] = upftbVerb_wca; }
	else{
		pinVerbs[0] = upftbVerb_wca; 
		pinVerbs[1] = pttbVerb_wca; }
	return;
}

// --------- Check if file to pin/unpin is s shorcut already pinned ----------- //
void CheckPinnedShorcut(char* file_cp, wchar_t* pinVerbs[], IShellDispatch* ISD_p) {
	char tbStore_ca[MAX_PATH] = {'\0'};
	sprintf(tbStore_ca, "%s\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar", getenv("AppData"));
	char tbShortCut_ca[MAX_PATH] = {'\0'};
	sprintf(tbShortCut_ca, "%s\\%s", tbStore_ca, file_cp);
	if (access(tbShortCut_ca, 0) == 0) {
		wchar_t* pttbVerb_wcp = pinVerbs[1];
		pinVerbs[1] = NULL;
		PinToTaskBar_core(tbStore_ca, file_cp, pinVerbs, ISD_p);
		pinVerbs[0] = pttbVerb_wcp; }
	return;
}

// -------------------------- "Pin to tas&kbar" Core -------------------------- //
void PinToTaskBar_core (char* dir_cp, char* file_cp, wchar_t* pinVerbs[], IShellDispatch* ISD_p) {
// Convert to wchar_t for Variant VT_BSTR type
	wchar_t	dir_wca[MAX_PATH] = {'\0'};
	mbstowcs(dir_wca, dir_cp, MAX_PATH);
	wchar_t	file_wca[MAX_PATH] = {'\0'};
	mbstowcs(file_wca, file_cp, MAX_PATH);
// Create a "Folder" Object of the directory containing the file to Pin/Unpin
	Folder *folder_p;
	VARIANTARG tmpVar_va;
	VariantInit(&tmpVar_va);
	tmpVar_va.vt = VT_BSTR;
	tmpVar_va.bstrVal = dir_wca;
	ISD_p->lpVtbl->NameSpace(ISD_p, tmpVar_va, &folder_p);
// Create a "FolderItem" Object of the file to Pin/Unpin
	FolderItem* folderItem_p;
	folder_p->lpVtbl->ParseName(folder_p, file_wca, &folderItem_p);
// Initialise the list of Verbs and search for "Pin to tas&kbar" || "Unpin from tas&kbar". If found: execute it
	int ct = 0;
	while (pinVerbs[ct] != NULL && ct < 2) {
		ExecuteVerb(pinVerbs[ct], folderItem_p);
		ct++; }
// Clean Up
	folderItem_p->lpVtbl->Release(folderItem_p);
	folder_p->lpVtbl->Release(folder_p);
}

// ------------------------------ "Execute Verb" ------------------------------ //
void ExecuteVerb(wchar_t* verb_wcp, FolderItem* folderItem_p) {
// MessageBoxW(NULL, verb_wcp, L"Done", 0);
	int verbLgt_i = wcsnlen(verb_wcp, MAX_PATH);
// Create a "FolderItemVerbs" Object of the Verbs corresponding to the file, including "Pin to tas&kbar" or "Unpin from tas&kbar"
	FolderItemVerbs* folderItemVerbs_p;
	folderItem_p->lpVtbl->Verbs(folderItem_p, &folderItemVerbs_p);
// Get the number of Verbs corresponding to the file to Pin/Unpin
	long nbVerb_l;
	folderItemVerbs_p->lpVtbl->get_Count(folderItemVerbs_p, &nbVerb_l);
// Create a "FolderItemVerb" Object to go through the list of Verbs until verb_wcp is found, and if found: execute it
	FolderItemVerb* folderItemVerb_p;
	wchar_t* fivName_wcp;
	wchar_t* tmpVar_wcp;
	VARIANTARG tmpVar_va;
	VariantInit(&tmpVar_va);
	tmpVar_va.vt = VT_I4;
	for (int ct = 0; ct < (int)nbVerb_l; ct++) {
		tmpVar_va.lVal = ct;
		folderItemVerbs_p->lpVtbl->Item(folderItemVerbs_p, tmpVar_va, &folderItemVerb_p);
		folderItemVerb_p->lpVtbl->get_Name(folderItemVerb_p, &fivName_wcp);
		if (wcsnlen(fivName_wcp, MAX_PATH) == verbLgt_i) {
			tmpVar_wcp = verb_wcp;
			while (*tmpVar_wcp && *tmpVar_wcp == *fivName_wcp) { tmpVar_wcp++; fivName_wcp++; }
			if (!*tmpVar_wcp && !*fivName_wcp) { folderItemVerb_p->lpVtbl->DoIt(folderItemVerb_p); break; } } }
// Clean Up
	folderItemVerb_p->lpVtbl->Release(folderItemVerb_p);
	folderItemVerbs_p->lpVtbl->Release(folderItemVerbs_p);	
}

// -------------------- Get arguments from command line A --------------------- //
// Notes:
//	- Personal preference for char* instead of the wchar_t* provided by "CommandLineToArgvW()"
//	- Probably works with double quoted arguments containing escaped quotes.. in most cases:
//		- "Such as this \"Double Quoted\" Argument with \"Escaped Quotes\" and \\\"Escaped BackSlash\"\\"
void CommandLineToArgvA(char* cmdLine_cp, char** args_cpa) {
	char endChar_c;
	while (*cmdLine_cp) {
		while (*cmdLine_cp && *cmdLine_cp == ' ') cmdLine_cp++;					// Trim white-spaces before the argument
		endChar_c = ' ';														// end of argument is defined as white-space..
		if (*cmdLine_cp == '\"') { endChar_c = '\"'; cmdLine_cp++; }			// ..or as a double quote if argument is between double quotes
		*args_cpa = cmdLine_cp;													// Save argument pointer
// Find end of argument ' ' or '\"', while skipping '\\\"' if endChar_c = '\"'
		char prevBackSlash_b = 0;
		while (*cmdLine_cp && (*cmdLine_cp != endChar_c || (endChar_c == '\"' && prevBackSlash_b))) {
			prevBackSlash_b = 0;
			char checkBackSlash_c = 0;
			while(*(cmdLine_cp-checkBackSlash_c) == '\\') {
				checkBackSlash_c++;
				prevBackSlash_b = !prevBackSlash_b; }
			cmdLine_cp++; }
		if(*cmdLine_cp) {
			*cmdLine_cp = 0; cmdLine_cp++; }
		args_cpa++; }
}

// --------------------------- "Write to Console A" --------------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
void WriteToConsoleA(char* msg_cp) {
	WriteConsoleA(consOut_vp, msg_cp, strlen(msg_cp), NULL, NULL);
}

// ------------------- "Write Integer as Hex to Console A" -------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
// void WriteHexToConsoleA(int num_i) {
	// char hex_ca[19] = {'\0'};
	// char* hex_cp = &hex_ca[17];
	// while(num_i != 0) {
		// int tmpVar_i = num_i % 16;
		// if( tmpVar_i < 10 ) *hex_cp = tmpVar_i + 48;
		// else *hex_cp = tmpVar_i + 55;
		// num_i = num_i / 16;
		// hex_cp--;}
	// *hex_cp = 'x'; hex_cp--;
	// *hex_cp = '0';
	// WriteConsoleA(consOut_vp, hex_cp, strlen(hex_cp), NULL, NULL);
// }

// --------------------------- "Write to Console W" --------------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
// void WriteToConsoleW(wchar_t* msg_cp) {
	// WriteConsoleW(consOut_vp, msg_cp, wcslen(msg_cp), NULL, NULL);
// }

// ---------------------------------------------------------------------------- //
// ----------------------------------- INFO ----------------------------------- //
// ---------------------------------------------------------------------------- //
// Pin To TaskBar for command line:
//   - Minimal reverse engineering of syspin.exe from https://www.technosys.net/products/utils/pintotaskbar
//   - With only "Pin to taskbar" and "Unpin from taskbar" functionalities included
//   - By default, pttb force Re-Pin any .exe/.lnk that is already pinned, but as a result: the programs gets re-pinned in last position
//   - Tested on Windows 10 Pro 64bit - Version 20H2 / build 19042.964 / locale en-US
//   - Syspin.exe was decompiled using Retargetable Decompiler from https://retdec.com
//   - Another helpful reverse engineering project of syspin.exe in C++ (much more faithful to the source) : https://github.com/airwolf2026/Win10Pin2TB

// Compiled with MSYS2/MinGW-w64:
//	$ gcc -o pttb pttb.c -Lmingw64/x86_64-w64-mingw32/lib -lole32 -loleaut32 -luuid -s -O3 -Wl,--gc-sections -nostartfiles --entry=pttb

// Usage:
//	> pttb Path\to\.exe\or\.lnk\to\PinToTaskbar
//	> pttb -u Path\to\.exe\or\.lnk\to\UnPinFromTaskBar

// Notes:
//   - 1st tried the registry method described here:
//     - https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
//     - Doesn't work anymore
//   - Then tried the PEB method described here:
//     - https://alexweinberger.com/main/pinning-network-program-taskbar-programmatically-windows-10/
//     - Doesn't work anymore either
//   - So pttb ended up being developed with the PE injection method used by syspin.exe from https://www.technosys.net
//     - Thanks Microsoft for making it a bit more difficult, I learned quite a bit with this little project

// --------------------------- Functions Prototype ---------------------------- //
// int access(const char* path, int mode);										// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess?view=msvc-160
// int sprintf(char* buffer, const char* format, ...);							// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-160
// void* __stdcall GetStdHandle(int nStdHandle);								// https://docs.microsoft.com/en-us/windows/console/getstdhandle
// void* GetCommandLineA();														// https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinea
// unsigned long strlen(const char *str);										// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strlen-wcslen-mbslen-mbslen-l-mbstrlen-mbstrlen-l?view=msvc-160
// int __stdcall WriteConsoleA(void* hConsoleOutput, const char* lpBuffer,int nNumberOfCharsToWrite, unsigned long* lpNumberOfCharsWritten,void* lpReserved);  // https://docs.microsoft.com/en-us/windows/console/writeconsole
// unsigned long GetFullPathNameA(char* lpFileName, unsigned long nBufferLength, char* lpBuffer, char** lpFilePart);  // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamea
// void* FindWindowA(char* lpClassName, char* lpWindowName);					// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa
// unsigned long GetWindowThreadProcessId( void* hWnd, unsigned long* lpdwProcessId);  // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid
// void* OpenProcess(unsigned long dwDesiredAccess, int  bInheritHandle, unsigned long dwProcessId);  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
// void* GetModuleHandleA(char* lpModuleName);									// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
// void* VirtualAlloc(void* lpAddress, unsigned long dwSize, unsigned long flAllocationType, unsigned long flProtect);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
// void* memcpy(void* dest, const void* src, unsigned long count);				// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=msvc-160
// void* VirtualAllocEx(void* hProcess, void* lpAddress, unsigned long dwSize, unsigned long flAllocationType, unsigned long flProtect);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
// int WriteProcessMemory(void*  hProcess, void* lpBaseAddress, void* lpBuffer, unsigned long nSize, unsigned long* lpNumberOfBytesWritten);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
// void* CreateRemoteThread(void* hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, unsigned long dwStackSize, LPTHREAD_START_ROUTINE startRoutine_lptsr, void* lpParameter, unsigned long dwCreationFlags, unsigned long* lpThreadId);  \\ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
// void* LoadLibraryW(wchar_t* lpLibFileName);									// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw
// void* GetModuleHandleW(wchar_t* lpModuleName);								// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
// int LoadStringW(void* hInstance, unsigned int uID, wchar_t* lpBuffer, int cchBufferMax);  // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringw
// int FreeLibrary(void* hLibModule);											// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
// long CoInitialize(void* pvReserved);											// https://docs.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-coinitialize
// long CoCreateInstance(REFCLSID  rclsid, LPUNKNOWN pUnkOuter, unsigned long dwClsContext, REFIID riid, void** ppv);  // https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
// void VariantInit(VARIANTARG *pvarg);											// https://docs.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantinit
// unsigned long wcsnlen(const wchar_t* str, unsigned long numberOfElements);	// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s?view=msvc-160
// void CoUninitialize();														// https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize
// unsigned long WaitForSingleObject(void* hHandle, unsigned long dwMilliseconds);  // https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
// int TerminateThread(void* hThread, unsigned long dwExitCode);				// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread
// int CloseHandle(void* hObject);												// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
// int VirtualFree(void* lpAddress, unsigned long dwSize, unsigned long dwFreeType);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
// int VirtualFreeEx(void* hProcess, void* lpAddress, unsigned long dwSize, unsigned long dwFreeType);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
// void ExitProcess(unsigned int uExitCode);									// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess

// ------------------------------ Windows Stuffs ------------------------------ //
// VARIANTARG: https://docs.microsoft.com/en-us/previous-versions/windows/embedded/ee487850(v=winembedded.80)
// IShellDispatch object: https://docs.microsoft.com/en-us/windows/win32/shell/ishelldispatch
// IShellDispatch.NameSpace method: https://docs.microsoft.com/en-us/windows/win32/shell/ishelldispatch-namespace
// Folder object: https://docs.microsoft.com/en-us/windows/win32/shell/folder
// Folder.ParseName method: https://docs.microsoft.com/en-us/windows/win32/shell/folder-parsename
// FolderItem object: https://docs.microsoft.com/en-us/windows/win32/shell/folderitem
// FolderItemVerbs object: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverbs
// FolderItemVerbs.Count property: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverbs-count
// FolderItemVerbs.Item method: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverbs-item
// FolderItemVerb object: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverb
// FolderItemVerb.Name property: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverb-name
// FolderItemVerb.DoIt method: https://docs.microsoft.com/en-us/windows/win32/shell/folderitemverb-doit

