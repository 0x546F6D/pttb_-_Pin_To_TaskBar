// # pttb - Pin To TaskBar

// Pin To TaskBar for command line:
//   - Minimal reverse engineering of syspin.exe from https://www.technosys.net/products/utils/pintotaskbar
//   - With only "Pin to taskbar" functionality included
//   - However, in order to overwrite shorcuts in TaskBar, pttb does Unpin & Re-Pin them, but the programs gets re-pinned in last position
//   - Tested on Windows 10 Pro 64bit - Version 2004 / build 19041.685 / locale en-US
//   - Syspin.exe was decompiled using Retargetable Decompiler from https://retdec.com
//   - Another helpful reverse engineering project of syspin.exe in C++, which is much more faithful to the source : https://github.com/airwolf2026/Win10Pin2TB

// Compiled with MSYS2/MinGW-w64:
//	$ gcc -o pttb pttb.c -Lmingw64/x86_64-w64-mingw32/lib -lole32 -loleaut32 -luuid -s -O3 -Wl,--gc-sections -nostartfiles --entry=pttb

// Usage:
//	> pttb PATH\TO\THE\PROGRAM\OR\SHORTCUT\TO\PIN\TO\TASKBAR

// Notes:
//   - 1st tried the registry method described here:
//     - https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
//     - Doesn't work anymore
//   - Then tried the PEB method described here:
//     - https://alexweinberger.com/main/pinning-network-program-taskbar-programmatically-windows-10/
//     - Doesn't work anymore either
//   - So pttb ended up being developed with the PE injection method used by syspin.exe from https://www.technosys.net
//     - Thanks Microsoft for making it a bit more difficult, I learned quite a bit with this little project

// #include <windows.h>
#include <Shldisp.h>
#include <stdint.h>
// #include <stdio.h>

// ----------------------- Project Functions Prototype ------------------------ //
static unsigned long __stdcall PinToTaskBar_func(char* pdata);					// "Pin to tas&kbar" Function to call once injected in "Progman"
void PinToTaskBar_core (char* pcFolder, char* pcFile, wchar_t* wcpPTTBVerb, wchar_t* wcpUPFTBVerb, IShellDispatch* ISDp);  // Core Function of "PinToTaskBar_func"
void ExecuteVerb(wchar_t* wcpVerb, FolderItem* FIp);							// Execute Verb if found
void CommandLineToArgvA(char* cpCmdLine, char** cpaArgs);						// Get arguments from command line.. just a personal preference for char* instead of the wchar_t* type provided by "CommandLineToArgvW()"
void WriteToConsoleA(char* cpMsg);												// "Write to Console A" function to save >20KB compared to printf and <stdio.h>
// void WriteIntToConsoleA(int iNum);											// "Write Integer as Hex to Console A" function to save >20KB compared to printf and <stdio.h>
// void WriteToConsoleW(wchar_t* cpMsg);										// "Write to Console W" function to save >20KB compared to printf and <stdio.h>

// --------------------------- Functions Prototype ---------------------------- //
int access(const char* path, int mode);											// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess?view=msvc-160
int sprintf(char* buffer, const char* format, ...);								// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/sprintf-sprintf-l-swprintf-swprintf-l-swprintf-l?view=msvc-160
// void* __stdcall GetStdHandle(int32_t nStdHandle);							// https://docs.microsoft.com/en-us/windows/console/getstdhandle
// void* GetCommandLineA();														// https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinea
// unsigned long strlen(const char *str);										// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strlen-wcslen-mbslen-mbslen-l-mbstrlen-mbstrlen-l?view=msvc-160
// int __stdcall WriteConsoleA(void* hConsoleOutput, const char* lpBuffer,int32_t nNumberOfCharsToWrite, unsigned long* lpNumberOfCharsWritten,void* lpReserved);  // https://docs.microsoft.com/en-us/windows/console/writeconsole
// unsigned long GetFullPathNameA(char* lpFileName, unsigned long nBufferLength, char* lpBuffer, char** lpFilePart);  // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamea
// void* FindWindowA(char* lpClassName, char* lpWindowName);					// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa
// unsigned long GetWindowThreadProcessId( void* hWnd, unsigned long* lpdwProcessId);  // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid
// void* OpenProcess(unsigned long dwDesiredAccess, int  bInheritHandle, unsigned long dwProcessId);  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
// void* GetModuleHandleA(char* lpModuleName);									// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
// void* VirtualAlloc(void* lpAddress, unsigned long dwSize, unsigned long flAllocationType, unsigned long flProtect);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
// void* memcpy(void* dest, const void* src, unsigned long count);				// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=msvc-160
// void* VirtualAllocEx(void* hProcess, void* lpAddress, unsigned long dwSize, unsigned long flAllocationType, unsigned long flProtect);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
// int WriteProcessMemory(void*  hProcess, void* lpBaseAddress, void* lpBuffer, unsigned long nSize, unsigned long* lpNumberOfBytesWritten);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
// void* CreateRemoteThread(void* hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, unsigned long dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, void* lpParameter, unsigned long dwCreationFlags, unsigned long* lpThreadId);  \\ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
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

// ----------------------------- Global Variables ----------------------------- //
void* __stdcall vp_ConsOut;

// --------------------------- entry point function --------------------------- //
void pttb() {
	vp_ConsOut = GetStdHandle(-11);
// Get arguments from command line
	const int iNbArgs = 1;														// number of expected arguments
	char*	cpaArgs[iNbArgs+1];													// 1st "argument" isnt really one: it's this program path
	char	caArgPath[MAX_PATH];												// Full path to exe or shortcut to Pin to TaskBar
	char*	cpCmdLine = GetCommandLineA();
	CommandLineToArgvA(cpCmdLine, cpaArgs);										// Get arguments from command line
// Check that an argument was passed
	if(!cpaArgs[1]) {
		WriteToConsoleA("\nERROR_BAD_ARGUMENTS: Arguments missing\n");
		WriteToConsoleA("Usage: > pttb PATH\\TO\\THE\\PROGRAM\\OR\\SHORTCUT\\TO\\PIN\\TO\\TASKBAR\n");
		ExitProcess(0xA0); }													// 0xA0 = ERROR_BAD_ARGUMENTS	
// Check if 1st argument is a path to a program or shortcut that exists, and get GetFullPathName if it does
	if(access(cpaArgs[1], 0) < 0 ) {
		WriteToConsoleA("\nERROR_FILE_NOT_FOUND: \""); WriteToConsoleA(cpaArgs[1]); WriteToConsoleA("\"\n");
		ExitProcess(0x2); }														// 0x2 = ERROR_FILE_NOT_FOUND
	GetFullPathNameA(cpaArgs[1], MAX_PATH, caArgPath,NULL);
// Get a Handle to the "Progman" process
	unsigned long ulProcessId;
	GetWindowThreadProcessId(FindWindowA("Progman", NULL), &ulProcessId);
	void*	vpProcess = OpenProcess(0x2A, 0, ulProcessId);						// 0x2A = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// Get relevant addresses to this current process, as well as the image size
	void*	vpModule		= GetModuleHandleA(NULL);		
	int64_t	vpmModule		= (int64_t)vpModule;
	int64_t	vpmPE			= vpmModule + *(int32_t*)(vpmModule + 0x3C);		// 0x3C = IMAGE_DOS_HEADER -> e_lfanew // Gives offset to IMAGE_NT_HEADERS
	unsigned long ulImage	= *(unsigned long*)(vpmPE + 0x50);					// 0x50 = IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> SizeOfImage // Gives the size of this current process in memory
	// WriteIntToConsoleA(ulImage); WriteToConsoleA("\n");
// Reserve a local region of memory equal to "ulImage" and make a copy of itself into it
	void*	vpLocVirtAlloc	= VirtualAlloc(NULL, ulImage, 0x3000, 0x40);		// 0x3000 = MEM_COMMIT | MEM_RESERVE // 0x40 = PAGE_EXECUTE_READWRITE
	int64_t	vpmLocVirtAlloc	= (int64_t)vpLocVirtAlloc;
	memcpy(vpLocVirtAlloc, vpModule, ulImage);
// Reserve a region of memory equal to "ulImage + MAX_PATH" in the "Progman" process
	void*	vpRemVirtAlloc	= VirtualAllocEx(vpProcess, NULL, ulImage + MAX_PATH, 0x3000, 0x40);
	int64_t	vpmRemVirtAlloc	= (int64_t)vpRemVirtAlloc;
// Check if any Virtual Address in the current process need to be relocated 
	int64_t	vpmRelocTbl		= (*(int32_t*)(vpmPE + 180) != 0) ? *(int32_t*)(vpmPE + 176) : 0;  // 176/180: IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> IMAGE_DATA_DIRECTORY -> Base relocation table address/size
	int64_t	vpmVirtRelocTbl	= vpmLocVirtAlloc + vpmRelocTbl;					// Address of the Relocation Table
	int64_t	iDelta 			= vpmRemVirtAlloc - vpmModule;						// Relocation Offset between the current process and the reserved memory region in the "Progman" process
// Relocate every block of virtual address
	while (vpmRelocTbl != 0) {
		int32_t	i32RelocBlkSiz = *(int32_t*)(vpmVirtRelocTbl + 4);				// Block size to relocate from Virtual Address (size of struct _IMAGE_BASE_RELOCATION included)
		vpmRelocTbl = vpmLocVirtAlloc + *(int32_t*)vpmVirtRelocTbl;				// Virtual Address relocation offset according ImageBase
		vpmVirtRelocTbl += 8;													// 8: size of struct _IMAGE_BASE_RELOCATION // jump to 1st Descriptor to relocate
		if (i32RelocBlkSiz >= 8) {												// Block size must be > size of struct _IMAGE_BASE_RELOCATION in order to have any Descriptor
			int32_t	i32RelocNbDesc = (i32RelocBlkSiz - 8) / 2;					// number of descriptors in this block: i32RelocBlkSiz in BYTE, but descriptors in int16_t
			for (int ct=0; ct<i32RelocNbDesc; ct++) {
				int16_t i16RelocDescOffset = *(int16_t*)vpmVirtRelocTbl & 0x0FFF;  // Get descriptor offset of Virtual address to relocate
				if (i16RelocDescOffset != 0) { *(int64_t*)(vpmRelocTbl + i16RelocDescOffset) += iDelta; }  // Add "iDelta" to the value at this address
				vpmVirtRelocTbl += 2; } }										// Go to next descriptor
		vpmRelocTbl = *(int32_t*)vpmVirtRelocTbl; }								// Get Virtual Address of next Block
// Remove wild breakpoint at beginning of main function -> still works fine without this line, probably because pttb doesnt have a main function
	// *(int8_t*)(vpmLocVirtAlloc+vpmPE-vpmModule+0x28) = 0x55;					// 0x28: IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER -> AddressOfEntryPoint; 0x55 -> push %rbp
// Inject local region of memory into "Progman" process region of memory
	WriteProcessMemory(vpProcess, vpRemVirtAlloc, vpLocVirtAlloc, ulImage, NULL);
	void*	pCommandBaseAdd = (void*)(vpmRemVirtAlloc + ulImage);
	WriteProcessMemory(vpProcess, pCommandBaseAdd, caArgPath, MAX_PATH, NULL);	// Copy the path to the file to pin to taskbar, into the extra memory of size "MAX_PATH"
// Run the "PinToTaskBar_func" in the "Progman" process, with the path to the file to pin to taskbar as a parameter
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)(iDelta + PinToTaskBar_func);
	void*	vpThread = CreateRemoteThread(vpProcess, NULL, 0, lpStartAddress, pCommandBaseAdd, 0, NULL);
// Wait for the Thread to finish and clean it up
	WaitForSingleObject(vpThread, 5000);
	TerminateThread(vpThread, 0);
	CloseHandle(vpThread);
// Clean Up Everything
	VirtualFree(vpLocVirtAlloc, 0, 0x8000);										// 0x8000 = MEM_RELEASE
	VirtualFreeEx(vpProcess, vpRemVirtAlloc, 0, 0x8000);
	CloseHandle(vpProcess);
	ExitProcess(0);
}

// ---------------------------- "Pin to tas&kbar" ----------------------------- //
// Note: Function to call once injected in "Progman"
static unsigned long __stdcall PinToTaskBar_func(char* cpdata) {
// Get directory and Filename from pdata
	char*	cpDir	= cpdata;
	char*	cpFile	= NULL;
	while (*cpdata) {
		if(*cpdata == '\\') cpFile = cpdata;
		cpdata++; }
	*cpFile = 0;
	cpFile += 1;
// Get "Pin to tas&kbar" and "Unpin from tas&kbar" Verbs in Windows locale
	wchar_t*	wcpPTTBVerb		= L"Pin to tas&kbar";
	wchar_t*	wcpUPFTBVerb	= L"Unpin from tas&kbar";
	void*		vpShell32		= LoadLibraryW(L"shell32.dll");
	LoadStringW(GetModuleHandleW(L"shell32.dll"), 5386, wcpPTTBVerb, MAX_PATH);		// 5386 = "Pin to tas&kbar" in en-us locale versions of Windows
	LoadStringW(GetModuleHandleW(L"shell32.dll"), 5387, wcpUPFTBVerb, MAX_PATH);	// 5387 = "Unpin from tas&kbar" in en-us locale versions of Windows
	FreeLibrary(vpShell32);
// Create COM Objects
	CoInitialize(NULL);
	IShellDispatch* ISDp;
	CoCreateInstance(&CLSID_Shell, NULL, 0x1, &IID_IShellDispatch, (void**)&ISDp);	// 0x1 = CLSCTX_INPROC_SERVER
// Check if Shorcut is already pinned, and if so: unpin it directly from %AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\shorcut.lnk, because Windows föks up when Unpinning+Pinning shorcuts with same path/name.lnk, but whose target/arguments have been modified..
	char	caTBStor[MAX_PATH] = { '\0' };
	sprintf(caTBStor, "%s\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar", getenv("AppData"));
	char	caTBShortCut[MAX_PATH] = { '\0' };
	sprintf(caTBShortCut, "%s\\%s", caTBStor, cpFile);
	if (access(caTBShortCut, 0) == 0) PinToTaskBar_core(caTBStor, cpFile, NULL, wcpUPFTBVerb, ISDp);
// Unpin Prog from taskbar if pinned and (Re-)Pin Prog/ShorCut
	PinToTaskBar_core(cpDir, cpFile, wcpPTTBVerb, wcpUPFTBVerb, ISDp);
// Clean Up
	ISDp->lpVtbl->Release(ISDp);
	CoUninitialize();
	// MessageBox(NULL, "Check the TaskBar", "Done", 0);
	return 0;
}

// -------------------------- "Pin to tas&kbar" Core -------------------------- //
void PinToTaskBar_core (char* pcFolder, char* pcFile, wchar_t* wcpPTTBVerb, wchar_t* wcpUPFTBVerb, IShellDispatch* ISDp) {
// Convert to wchar_t for Variant VT_BSTR type
	wchar_t	wcaFold[MAX_PATH] = { '\0' };
	mbstowcs(wcaFold, pcFolder, MAX_PATH);
	wchar_t	wcaFilNam[MAX_PATH] = { '\0' };
	mbstowcs(wcaFilNam, pcFile, MAX_PATH);
// Create a "Folder" Object of the directory containing the file to Pin/Unpin
	Folder	*FOLDp;
	VARIANTARG varTmp;
	VariantInit(&varTmp);
	varTmp.vt = VT_BSTR;
	varTmp.bstrVal = wcaFold;
	ISDp->lpVtbl->NameSpace(ISDp, varTmp, &FOLDp);
// Create a "FolderItem" Object of the file to Pin/Unpin
	FolderItem* FIp;
	FOLDp->lpVtbl->ParseName(FOLDp, wcaFilNam, &FIp);
// Initialise the list of Verbs and search for "Unpin from tas&kbar". If found: execute it
	if(wcpUPFTBVerb) ExecuteVerb(wcpUPFTBVerb, FIp);
// Initialise the list of Verbs and search for "Pin to tas&kbar". If found: execute it
	if(wcpPTTBVerb) ExecuteVerb(wcpPTTBVerb, FIp);
// Clean Up
	FIp->lpVtbl->Release(FIp);
	FOLDp->lpVtbl->Release(FOLDp);
}

// ------------------------------ "Execute Verb" ------------------------------ //
void ExecuteVerb(wchar_t* wcpVerb, FolderItem* FIp) {
	int		iVerbLgt = wcsnlen(wcpVerb, MAX_PATH);
// Create a "FolderItemVerbs" Object of the Verbs corresponding to the file, including "Pin to tas&kbar" or "Unpin from tas&kbar"
	FolderItemVerbs* FIVSp;
	FIp->lpVtbl->Verbs(FIp, &FIVSp);
// Get the number of Verbs corresponding to the file to Pin/Unpin
	long	lNbVerb;
	FIVSp->lpVtbl->get_Count(FIVSp, &lNbVerb);
// Create a "FolderItemVerb" Object to go through the list of Verbs until wcpVerb is found, and if found: execute it
	FolderItemVerb* FIVp;
	wchar_t* wcpFIVNam;
	wchar_t* wcpTmp;
	VARIANTARG varTmp;
	VariantInit(&varTmp);
	varTmp.vt = VT_I4;
	for (int ct = 0; ct < (int)lNbVerb; ct++) {
		varTmp.lVal = ct;
		FIVSp->lpVtbl->Item(FIVSp, varTmp, &FIVp);
		FIVp->lpVtbl->get_Name(FIVp, &wcpFIVNam);
		if (wcsnlen(wcpFIVNam, MAX_PATH) == iVerbLgt) {
			wcpTmp = wcpVerb;
			while (*wcpTmp && *wcpTmp == *wcpFIVNam) { wcpTmp++; wcpFIVNam++; }
			if (!*wcpTmp && !*wcpFIVNam) { FIVp->lpVtbl->DoIt(FIVp); break; } } }
// Clean Up
	FIVp->lpVtbl->Release(FIVp);
	FIVSp->lpVtbl->Release(FIVSp);	
}

// -------------------- Get arguments from command line A --------------------- //
// Notes:
//	- Personal preference for char* instead of the wchar_t* provided by "CommandLineToArgvW()"
//	- Works with double quoted arguments containing escaped quotes: "Such as this \"Double Quoted\" Argument with \"Escaped Quotes\""
void CommandLineToArgvA(char* cpCmdLine, char** cpaArgs) {
	char	cEnd;
	while (*cpCmdLine) {
		while (*cpCmdLine && *cpCmdLine == ' ') cpCmdLine++;					// Trim white-spaces before the argument
		cEnd = ' ';																// end of argument is defined as white-space..
		if (*cpCmdLine == '\"') { cEnd = '\"'; cpCmdLine++; }					// ..or as a double quote if argument is between double quotes
		*cpaArgs = cpCmdLine;													// Save argument pointer
		while (*cpCmdLine && (*cpCmdLine != cEnd || (cEnd == '\"' && *(cpCmdLine-1) == '\\'))) cpCmdLine++;  // Find end of argument ' ' or '\"', while skipping '\\\"' if cEnd = '\"'
		*cpCmdLine = 0;	cpCmdLine++;
		cpaArgs++; }
}

// --------------------------- "Write to Console A" --------------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
void WriteToConsoleA(char* cpMsg) {
	WriteConsoleA(vp_ConsOut, cpMsg, strlen(cpMsg), NULL, NULL);
}

// ------------------- "Write Integer as Hex to Console A" -------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
// void WriteIntToConsoleA(int iNum) {
	// char caHex[19] = {'\0'};
	// char* cpHex = &caHex[17];
	// while(iNum != 0) {
		// int iTmp = iNum % 16;
		// if( iTmp < 10 ) *cpHex = iTmp + 48;
		// else *cpHex = iTmp + 55;
		// iNum = iNum / 16;
		// cpHex--;}
	// *cpHex = 'x'; cpHex--;
	// *cpHex = '0';
	// WriteConsoleA(vp_ConsOut, cpHex, strlen(cpHex), NULL, NULL);
// }

// --------------------------- "Write to Console W" --------------------------- //
// Note: Saves >20KB compared to printf and <stdio.h>
// void WriteToConsoleW(wchar_t* cpMsg) {
	// WriteConsoleW(vp_ConsOut, cpMsg, wcslen(cpMsg), NULL, NULL);
// }
