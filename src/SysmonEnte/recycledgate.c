#include "recycledgate.h"

DWORD GetSyscall(DWORD dwCryptedHash, Syscall* pSyscall) {

	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

	PVOID pGate = NULL, pNtdllBase = NULL, pStub = NULL;
	PDWORD pdwAddrOfNames = NULL, pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	DWORD dwSyscallNr = 0, dwSuccess = FAIL;
	WORD wIdxStub = 0, wIdxfName = 0;
	PCHAR pFunctionName = NULL;
	BOOL bHooked = FALSE;

	pNtdllBase = findNtDll();
	if (pNtdllBase == NULL)
		goto exit;

	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	for (wIdxfName = 0; wIdxfName < pExportDir->NumberOfNames; wIdxfName++) {

		pFunctionName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[wIdxfName]);
		pStub = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[wIdxfName]]);

		if (djb2((PCSTR)pFunctionName) == xor_hash(dwCryptedHash))
			break;

	}

	if (pStub == NULL)
		goto exit;

	for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++) {

		if (*((PBYTE)pStub + wIdxStub) == 0xe9) { // This syscall stub is hooked
			bHooked = TRUE;
			break;
		}

		if (*((PBYTE)pStub + wIdxStub) == 0xc3) // Too far
			goto exit;

		if (*((PBYTE)pStub + wIdxStub) == 0x4c && *((PBYTE)pStub + wIdxStub + 1) == 0x8b && *((PBYTE)pStub + wIdxStub + 2) == 0xd1 &&
			*((PBYTE)pStub + wIdxStub + 3) == 0xb8 && *((PBYTE)pStub + wIdxStub + 6) == 0x00 && *((PBYTE)pStub + wIdxStub + 7) == 0x00) {

			BYTE low = *((PBYTE)pStub + 4 + wIdxStub);
			BYTE high = *((PBYTE)pStub + 5 + wIdxStub);

			dwSyscallNr = (high << 8) | low;

			break;

		}
	}

	if (bHooked) { // Check syscalls around our hooked syscall


		for (wIdxfName = 1; wIdxfName <= pExportDir->NumberOfFunctions; wIdxfName++) {
			if ((PBYTE)pStub + wIdxfName * DOWN < ((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[pExportDir->NumberOfFunctions - 1]])) {
				if (
					*((PBYTE)pStub + wIdxfName * DOWN) == 0x4c
					&& *((PBYTE)pStub + 1 + wIdxfName * DOWN) == 0x8b
					&& *((PBYTE)pStub + 2 + wIdxfName * DOWN) == 0xd1
					&& *((PBYTE)pStub + 3 + wIdxfName * DOWN) == 0xb8
					&& *((PBYTE)pStub + 6 + wIdxfName * DOWN) == 0x00
					&& *((PBYTE)pStub + 7 + wIdxfName * DOWN) == 0x00) {

					BYTE high = *((PBYTE)pStub + 5 + wIdxfName * DOWN);
					BYTE low = *((PBYTE)pStub + 4 + wIdxfName * DOWN);
					dwSyscallNr = ((high << 8) | low) - wIdxfName;

					pStub = (PVOID)((PBYTE)pStub + wIdxfName * DOWN);

					break;

				}
			}

			if ((PBYTE)pStub + wIdxfName * UP > ((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[0]])) {

				if (*((PBYTE)pStub + wIdxfName * UP) == 0x4c
					&& *((PBYTE)pStub + 1 + wIdxfName * UP) == 0x8b
					&& *((PBYTE)pStub + 2 + wIdxfName * UP) == 0xd1
					&& *((PBYTE)pStub + 3 + wIdxfName * UP) == 0xb8
					&& *((PBYTE)pStub + 6 + wIdxfName * UP) == 0x00
					&& *((PBYTE)pStub + 7 + wIdxfName * UP) == 0x00) {

					BYTE high = *((PBYTE)pStub + 5 + wIdxfName * UP);
					BYTE low = *((PBYTE)pStub + 4 + wIdxfName * UP);
					dwSyscallNr = ((high << 8) | low) + wIdxfName;

					pStub = (PVOID)((PBYTE)pStub + wIdxfName * UP);

					break;

				}
			}
		}
	}

	if (pStub && dwSyscallNr) { // Last step: Search for syscall ; ret to use directly
		for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++) {
			if (*((PBYTE)pStub + wIdxStub) == 0x0f && *((PBYTE)pStub + wIdxStub + 1) == 0x05 && *((PBYTE)pStub + wIdxStub + 2) == 0xc3) { // syscall; ret - sequence?
				pGate = (LPVOID)((PBYTE)pStub + wIdxStub);
				break;
			}
		}
	}


	if (pGate == NULL || dwSyscallNr == 0x00)
		goto exit;

	pSyscall->pRecycledGate = pGate;
	pSyscall->dwSyscallNr = dwSyscallNr;

	dwSuccess = SUCCESS;

exit:

	return dwSuccess;

}

PVOID findNtDll(void) {

	PPEB pPeb = NULL;
	PPEB_LDR_DATA pLdrData = NULL;
	PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
	PUNICODE_STR pDllName = NULL;

	PVOID pNtdllBase = NULL;

	pPeb = (PPEB)__readgsqword(0x60);
	pLdrData = pPeb->pLdr;
	pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InMemoryOrderModuleList.Flink;

	do {

		pDllName = &pModuleEntry->BaseDllName;

		if (pDllName->pBuffer == NULL)
			return NULL;

		if (djb2_unicode(toLowerW(pDllName->pBuffer)) == xor_hash(0x6391f6a9)) {
			pNtdllBase = (PVOID)pModuleEntry->DllBase;
			break;
		}

		pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InMemoryOrderModuleList.Flink;

	} while (pModuleEntry != pModuleStart);

	return pNtdllBase;

}

unsigned long
xor_hash(unsigned long hash) {
	return hash ^ HASH_KEY;
}