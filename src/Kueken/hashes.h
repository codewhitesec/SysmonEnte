#ifndef HASHES_H
#define HASHES_H

#include <windows.h>
#include <evntprov.h>

// ---- NTDLL ----
#define CRYPTED_HASH_NTDLL 0x6391f6a9
#define CRYPTED_HASH_ETWEVENTWRITE 0x65ea9366
#define CRYPTED_HASH_ETWEVENTWRITEFULL 0xae6230f1

// ----  KERNEL32 ----
#define H_LIB_KERNEL32 0x3102ad31 
#define H_API_COPYMEMORY 0x14d8cfcf
#define H_API_LOADLIBRARYA 0x1efdb3bf

// ---- shlwapi.dll ----
#define H_LIB_SHLWAPI 0xe64fd763
#define H_API_STRSTRA 0x4ef4617c
#define H_API_STRSTRW 0x473829d3

typedef PCWSTR(WINAPI* STRSTRW)(PCWSTR, PCWSTR);
typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);


#endif
