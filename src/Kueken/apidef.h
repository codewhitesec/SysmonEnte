
#ifndef _APIDEF_H
#define _APIDEF_H

#include "windows.h"
#include <evntprov.h>

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int(WINAPI* LSTRLENA)(LPCSTR);
typedef void(WINAPI* COPYMEMORY)(PVOID, void*, SIZE_T);

typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);
typedef PCWSTR(WINAPI* STRSTRW)(PCWSTR, PCWSTR);

typedef ULONG(NTAPI* _EtwEventWriteFull)(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	USHORT EventProperty,
	LPCGUID ActivityId,
	LPCGUID RelatedActivityId,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);

#endif