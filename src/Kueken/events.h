#ifndef EVENTS_H
#define EVENTS_H

#include "windows.h"

#define EVENT_PROCESSACCESS 10

#pragma pack(1)
typedef struct ProcessAccess {

	wchar_t* pRuleName;
	size_t sizeRuleName;
	wchar_t* pUtcTime;
	size_t sizeUtcTime;
	void* psrcGUID;
	size_t sizesrcguid;
	void* ppidsrc;
	size_t sizepidsrc;
	void* ptidsrc;
	size_t sizetidsrc;
	wchar_t* psourceimage;
	size_t sizesourceimage;
	void* ptarGUID;
	size_t sizetarGUID;
	void* ppiddest;
	size_t sizepiddest;
	wchar_t* ptargetimage;
	size_t sizetargetimage;
	PACCESS_MASK pGrantedAccess;
	size_t sizeGrantedAccess;
	wchar_t* pCalltrace;
	size_t sizecalltrace;
	wchar_t* pSourceUser;
	size_t sizeSourceUser;
	wchar_t* pTargetUser;
	size_t sizetargetUser;

} ProcessAccess, * PProcessAccess;

#pragma pack()

#endif