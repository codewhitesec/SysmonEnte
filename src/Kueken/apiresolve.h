#ifndef _APIRESOLVE_H
#define _APIRESOLVE_H

#include <windows.h>

#include "apidef.h"
#include "hashes.h"
#include "peb.h"

PVOID GetFunctionPtr(unsigned long, unsigned long);

PVOID getDllBase(unsigned long);
PVOID loadDll(unsigned long);
PVOID loadDll_byName(PSTR);
PVOID parseHdrForPtr(PBYTE, unsigned long);
PVOID followExport(char*, unsigned long);
unsigned long xorHash(unsigned long);

unsigned long djb2(PCSTR str);
unsigned long djb2_unicode(PCWSTR str);
PSTR toLowerA(PSTR str);
PWSTR toLowerW(PWSTR str);

#endif