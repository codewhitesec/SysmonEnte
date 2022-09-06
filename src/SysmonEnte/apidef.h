
#ifndef APIDEF_H
#define APIDEF_H

#include "tlhelp32.h"

typedef BOOL(WINAPI* PROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* PROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);
typedef HMODULE(WINAPI* GETMODULEHANDLEA)(LPCSTR);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef LPSTR(WINAPI* LSTRCATA)(LPSTR, LPSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef int(WINAPI* LSTRLENA)(LPCSTR);
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef void(WINAPI* COPYMEMORY)(PVOID, void*, SIZE_T);
typedef LPWSTR(WINAPI* LSTRCATW)(LPWSTR, LPCWSTR);
typedef int (WINAPI* LSTRLENW)(LPCWSTR);
typedef HANDLE(WINAPI* CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
typedef int(WINAPI* LSTRCMPW)(LPCWSTR, LPCWSTR);
typedef int (WINAPI* LSTRCMPA)(LPCSTR, LPCSTR);
typedef BOOL(WINAPI* LOOKUPPRIVILEGEVALUEA)(LPCSTR, LPCSTR, PLUID);
typedef DWORD(WINAPI* GETMODULEFILENAMEEXA)(HANDLE, HMODULE, LPSTR, DWORD);
typedef DWORD(WINAPI* GETMODULEFILENAMEEXW)(HANDLE, HMODULE, LPWSTR, DWORD);
typedef BOOL(WINAPI* GETMODULEBASENAMEW)(HANDLE, HMODULE, LPWSTR, DWORD);
typedef HMODULE(WINAPI* GETMODULEHANDLE)(LPCSTR);


typedef BOOL(WINAPI* LOOKUPACCOUNTSIDA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI* GETUSERNAMEA)(LPSTR, LPDWORD);
typedef BOOL(WINAPI* LOOKUPACCOUNTUSERIDA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI* GETTOKENINFORMATION)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI* LOOKUPPRIVILEGENAMEA)(LPCSTR, PLUID, LPSTR, LPDWORD);
typedef BOOL(WINAPI* IMPERSONATELOGGEDONUSER)(HANDLE);

typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);

typedef BOOL(WINAPI* ENUMPROCESSMODULES)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD(WINAPI* GETMODULEFILENAMEEXA)(HANDLE, HMODULE, LPSTR, DWORD);

#endif