// # pttb - Pin To TaskBar

// Pin To TaskBar in C:
//   - Minimal reverse engineering of syspin.exe from https://www.technosys.net/products/utils/pintotaskbar
//   - With only "Pin to taskbar" functionality included, as I didnt need the others
//   - It works on my Windows 10 Pro, build 19041.630, locale en-US
//   - Syspin.exe was decompiled using Retargetable Decompiler from https://retdec.com
//   - Another helpful reverse engineering project of syspin.exe in C++, which is much more faithful to the source: https://github.com/airwolf2026/Win10Pin2TB

// Compiled with MSYS2/MinGW-w64:
//   $ gcc -o pttb pttb.c -Lmingw64/x86_64-w64-mingw32/lib -lole32 -loleaut32 -luuid -s -O3 -Wl,--gc-sections -nostartfiles --entry=pttb

// Usage:
//   > pttb PATH\TO\THE\PROGRAM\OR\SHORTCUT\TO\PIN\TO\TASKBAR

// Notes:
//   - 1st tried the registry method described here:
//     - https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
//     - Doesn't work anymore
//   - Then tried the PEB method described here:
//     - https://alexweinberger.com/main/pinning-network-program-taskbar-programmatically-windows-10/
//     - Doesn't work anymore either
//   - So I ended up using the PE injection method used by syspin.exe from https://www.technosys.net
//     - Thanks Microsoft for making it a bit more difficult, I learned quite a bit with this little project

// #include <windows.h>
#include <Shldisp.h>
#include <stdint.h>
// #include <unistd.h>
// #include <stdio.h>

// -------------------- Project Function Prototypes --------------------
static DWORD WINAPI PinToTaskBar_func(LPSTR pdata);																	// "Pin to tas&kbar" Function to call once injected in "Progman"
void GetCommandLineArgvA(LPSTR pCommandLine, LPSTR* aArgs);															// Get arguments from command line.. just a personal preference for char*/LPSTR instead of the wchar_t*/LPWSTR type provided by "CommandLineToArgvW()"
void WriteToConsoleA(LPSTR lpMsg);																					// "Write to Console A" function instead of printf and <stdio.h>
// void WriteIntToConsoleA(int num);																					// "Write Integer as Hex to Console A" function instead of printf and <stdio.h>
// void WriteToConsoleW(LPWSTR lpMsg);																					// "Write to Console W" function instead of printf and <stdio.h>

// -------------------- C Function Prototypes --------------------
// int sprintf(char *str, const char *format, ...);
int access(const char *pathname, int how);

// -------------------- Global Variables --------------------
HANDLE WINAPI hdConsoleOut;

// -------------------- entry point function --------------------
void pttb() {
	hdConsoleOut = GetStdHandle(-11);
// Get arguments from command line
	LPSTR pCommandLine = GetCommandLineA();
	const int nbArgs = 1;																							// number of expected arguments
	LPSTR aArgs[nbArgs+2];																							// 1st "argument" isnt really one: it's this program path
	GetCommandLineArgvA(pCommandLine, aArgs);																		// Get arguments from command line
// Check that an argument was passed
	if(!aArgs[1]) {
		WriteToConsoleA("ERROR: Argument missing\n");
		WriteToConsoleA("Usage: > tbs PATH\\TO\\THE\\PROGRAM\\OR\\SHORTCUT\\TO\\PIN\\TO\\TASKBAR\n");
		ExitProcess(0xA0); } // ERROR_BAD_ARGUMENTS	
// Check if 1st argument is a path to a program or shortcut that exists
	if(access(aArgs[1], 0) < 0 ) {
		WriteToConsoleA("ERROR: \""); WriteToConsoleA(aArgs[1]); WriteToConsoleA("\" not found\n");
		ExitProcess(0x2); } // ERROR_FILE_NOT_FOUND
// Get a Handle to the "Progman" process
	DWORD dwProcessId;
	GetWindowThreadProcessId(FindWindowA("Progman", NULL), &dwProcessId);
	HANDLE hdProcess = OpenProcess(42, 0, dwProcessId);
// Get relevant addresses to this current process, as well as the image size
	HMODULE hdModule		= GetModuleHandle(NULL);		
	int64_t adrModule		= (int64_t)hdModule;
	int64_t adrPE			= adrModule + (int64_t)*(int32_t *)(adrModule + 0x3C);									// 0x3C: IMAGE_DOS_HEADER -> e_lfanew // Gives offset to IMAGE_NT_HEADERS
	uint32_t szImage		= (uint32_t)*(int64_t *)(adrPE + 0x50);													// 0x50: IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> SizeOfImage // Gives the size of this current process in memory
	// WriteIntToConsoleA(szImage);
// Reserve a local region of memory equal to "szImage" and make a copy of itself into it
	LPVOID lpVirtAlloc		= VirtualAlloc(NULL, (SIZE_T)szImage, 0x3000, 64);
	int64_t adrVirtAlloc	= (int64_t)lpVirtAlloc;
	memcpy_s((void*)lpVirtAlloc, (SIZE_T)szImage, (const void*)hdModule, szImage);
// Reserve a region of memory equal to "szImage + MAX_PATH" in the "Progman" process
	LPVOID lpVirtAllocEx	= VirtualAllocEx(hdProcess, NULL, (SIZE_T)(szImage + MAX_PATH), 0x3000, 64);
	int64_t adrVirtAllocEx	= (int64_t)lpVirtAllocEx;
// Check if any Virtual Address in the current process need to be relocated 
	int64_t vRelocVirtAdd	= ((int64_t)*(int32_t *)(adrPE + 180) != 0) ? (int64_t)*(int32_t *)(adrPE + 176) : 0;	// 176/180: IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> IMAGE_DATA_DIRECTORY -> Base relocation table address/size
	int64_t pRelocVirtAdd	= adrVirtAlloc + vRelocVirtAdd;															// Address of the Relocation Table
	int64_t delta 			= adrVirtAllocEx - adrModule;															// Relocation Offset between the current process and the reserved memory region in the "Progman" process
// Relocate every block of virtual address
	while (vRelocVirtAdd != 0) {
		int32_t RelocBlockSize	= (int32_t)*(int32_t*)(pRelocVirtAdd + 4);											// Block size to relocate from Virtual Address (size of struct _IMAGE_BASE_RELOCATION included)
		vRelocVirtAdd		= adrVirtAlloc + (int64_t)*(int32_t*)pRelocVirtAdd;										// Virtual Address relocation offset according ImageBase
		pRelocVirtAdd	   += 8;																					// 8: size of struct _IMAGE_BASE_RELOCATION // jump to 1st Descriptor to relocate
		if (RelocBlockSize >= 8) {																					// Block size must be > size of struct _IMAGE_BASE_RELOCATION in order to have any Descriptor
			int32_t RelocNbDesc	= (RelocBlockSize - 8) / 2;															// number of Blocks to relocate: RelocBlockSize in BYTE, but relocation done in int16_t
			for (int32_t ct=0; ct<RelocNbDesc; ct++) {
				int16_t vRelocDescOffset = (int16_t)*(int16_t*)pRelocVirtAdd & 0x0FFF;								// Get descriptor offset of Virtual address to relocate
				if (vRelocDescOffset != 0) { *(int64_t*)(vRelocVirtAdd + vRelocDescOffset) += delta; }				// Add "delta" to the value at this address
				pRelocVirtAdd += 2; }}																				// Go to next descriptor
		vRelocVirtAdd = (int64_t)*(int32_t*)pRelocVirtAdd;}															// Get Virtual Address of next Block
// Remove wild breakpoint at beginning of main function -> still works fine without this line, probably because I dont use a main function
	// *(int8_t*)(adrVirtAlloc+adrPE-adrModule+0x28) = 0x55;															// 0x28: IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> AddressOfEntryPoint; 0x55 -> push %rbp
// Inject local region of memory into "Progman" process region of memory
	WriteProcessMemory(hdProcess, lpVirtAllocEx, (LPCVOID)lpVirtAlloc, szImage, NULL);
	LPVOID pCommandBaseAdd = (LPVOID)(adrVirtAllocEx + (int64_t)szImage);
	WriteProcessMemory(hdProcess, pCommandBaseAdd, (LPCVOID)(aArgs[1]), MAX_PATH, NULL);							// Copy the path to the file to pin to taskbar, into the extra memory of size "MAX_PATH"
// Run the "PinToTaskBar_func" in the "Progman" process, with the path to the file to pin to taskbar as a parameter
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)((LPBYTE)lpVirtAllocEx - (LPBYTE)hdModule + (DWORD_PTR)((LPBYTE)PinToTaskBar_func));
	LPVOID lpParameter = (LPVOID)((LPBYTE)lpVirtAllocEx + szImage);
	HANDLE hdThread = CreateRemoteThread(hdProcess, NULL, 0, lpStartAddress, lpParameter, 0, NULL);
// Wait for the Thread to finish and clean it up
	WaitForSingleObject(hdThread, 5000);
	TerminateThread(hdThread, 0);
	CloseHandle(hdThread);
// Clean Up Everything
	VirtualFree(lpVirtAlloc, 0, 0x8000);
	VirtualFreeEx(hdProcess, lpVirtAllocEx, 0, 0x8000);
	CloseHandle(hdProcess);
	ExitProcess(0);
}

// -------------------- "Pin to tas&kbar" -------------------- Function to call once injected in "Progman"
static DWORD WINAPI PinToTaskBar_func(LPSTR pdata) {
// Get directory Path and Filename from pdata
	LPSTR pPath = pdata;
	LPSTR pFile = NULL;
	while (*pdata) {
		if(*pdata == '\\') pFile = pdata;
		++pdata;}
	*pFile = 0;
	pFile += 1;
// Convert to wchar_t for Variant VT_BSTR type
	wchar_t wcFolder[MAX_PATH] = {'\0'};
	mbstowcs_s(NULL, wcFolder, MAX_PATH, pPath, MAX_PATH);
	wchar_t wcFileName[MAX_PATH] = {'\0'};
	mbstowcs_s(NULL, wcFileName, MAX_PATH, pFile, MAX_PATH);
// Get "Pin to tas&kbar" verb in Windows locale
	wchar_t* wcPinToTaskBar = L"Pin to tas&kbar";
	HMODULE hmLoadLibShell = LoadLibraryW(L"shell32.dll");
	LoadStringW(GetModuleHandleW(L"shell32.dll"), 5386, (LPWSTR)wcPinToTaskBar, MAX_PATH);							// Should be "Pin to tas&kbar" in en-us locale versions of Windows
	FreeLibrary(hmLoadLibShell);
	int lgtPTB = wcsnlen_s((const wchar_t*)wcPinToTaskBar, MAX_PATH);
// Create COM Objects
	CoInitialize(NULL);
	IShellDispatch* pISD;
	CoCreateInstance(&CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, &IID_IShellDispatch, (LPVOID*)&pISD);
// Create a "Folder" Object of the directory containing the file to pin to taskbar
	VARIANTARG varTmp;
	VariantInit(&varTmp);
	varTmp.vt = VT_BSTR;
	varTmp.bstrVal = (BSTR)wcFolder;
	Folder *pFolder;
	pISD->lpVtbl->NameSpace(pISD, varTmp, &pFolder);
// Create a "FolderItem" Object of the file to pin to taskbar
	FolderItem* pFI;
	pFolder->lpVtbl->ParseName(pFolder, (BSTR)(wcFileName), &pFI);
// Create a "FolderItemVerbs" Object of the verbs corresponding to the file, including "Pin to tas&kbar"
	FolderItemVerbs* pFIVs;
	pFI->lpVtbl->Verbs(pFI, &pFIVs);
// Get the number of verbs corresponding to the file to pin to taskbar
	LONG NbVerbs;
	pFIVs->lpVtbl->get_Count(pFIVs, &NbVerbs);
	// char cMsg[MAX_PATH] = {'\0'};
	// sprintf(cMsg, "NbVerbs : %d", NbVerbs);
	// MessageBox(NULL, cMsg, "Number of Verbs", 0);
// Create a "FolderItemVerb" Object, go through the list of verbs until "Pin to tas&kbar" is found, then execute it
	FolderItemVerb* pFIV;
	varTmp.vt = VT_I4;
	for (int i = 0; i < NbVerbs; i++) {
		varTmp.lVal = i;
		pFIVs->lpVtbl->Item(pFIVs, varTmp, &pFIV);
		BSTR pFIVName;
		pFIV->lpVtbl->get_Name(pFIV, &pFIVName);
		if (wcsnlen_s(pFIVName, MAX_PATH) == lgtPTB) {
			while (*wcPinToTaskBar && *wcPinToTaskBar == *pFIVName) { wcPinToTaskBar++; pFIVName++; }
			if (!*wcPinToTaskBar && !*pFIVName) { pFIV->lpVtbl->DoIt(pFIV); break; }}}
// Clean Up
	pFIV->lpVtbl->Release(pFIV);
	pFIVs->lpVtbl->Release(pFIVs);
	pFI->lpVtbl->Release(pFI);
	pFolder->lpVtbl->Release(pFolder);
	pISD->lpVtbl->Release(pISD);
	CoUninitialize();
	// MessageBox(NULL, "Check the TaskBar", "Done", 0);
	return 0;
}

// -------------------- Get arguments from command line -------------------- function.. just a personal preference for char*/LPSTR instead of the wchar_t*/LPWSTR type provided by "CommandLineToArgvW()"
void GetCommandLineArgvA(LPSTR pCommandLine, LPSTR* aArgs) {
	while (*pCommandLine) {
		while (*pCommandLine && *pCommandLine == ' ') pCommandLine++;												// Trim white-spaces before the argument
		char cEnd = ' ';																							// end of argument is defined as white-space..
		if (*pCommandLine == '\"') { pCommandLine++; cEnd = '\"'; }													// ..or as a double quote if argument is between double quotes
		*aArgs = pCommandLine;																						// Save argument pointer
		while (*pCommandLine && *pCommandLine != cEnd) pCommandLine++;
		if (*pCommandLine) *pCommandLine = 0;																		// Set NULL separator between arguments
		pCommandLine++;
		aArgs++; }
	*aArgs = 0;
}

// -------------------- "Write to Console A" -------------------- function instead of printf and <stdio.h>
void WriteToConsoleA(LPSTR lpMsg) {
	WriteConsoleA(hdConsoleOut, lpMsg, strlen(lpMsg), NULL, NULL);
}

// -------------------- "Write Integer as Hex to Console A" -------------------- function instead of printf and <stdio.h>
// void WriteIntToConsoleA(int num) {
	// char ahex[19] = {'\0'};
	// char* phex = (char*)(&ahex + 18);
	// while(num != 0) {
		// int var = num % 16;
		// if( var < 10 ) *phex = var + 48;
		// else *phex = var + 55;
		// num = num / 16;
		// phex--;}
	// *phex = 'x';
	// phex--;
	// *phex = '0';
	// WriteConsoleA(hdConsoleOut, phex, strlen(phex), NULL, NULL);
// }

// -------------------- "Write to Console W" -------------------- function instead of printf and <stdio.h>
// void WriteToConsoleW(LPWSTR lpMsg) {
	// WriteConsoleW(hdConsoleOut, lpMsg, wcslen(lpMsg), NULL, NULL);
// }
