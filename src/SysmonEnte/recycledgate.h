#ifndef RECYCLEDGATE_H
#define RECYCLEDGATE_H

#include "windows.h"

#include "misc.h"
#include "peb.h"

#define FAIL 0
#define SUCCESS 1

#define HASH_KEY 0x41424344
#define SYS_STUB_SIZE 32

#define UP -32
#define DOWN 32

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct Syscall {

    DWORD dwSyscallNr;
    PVOID pRecycledGate;

} Syscall, *PSyscall;


DWORD GetSyscall(DWORD crypted_hash, PSyscall pSyscall);
extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern int DoSyscall();

PVOID findNtDll(void);
unsigned long xor_hash(unsigned long hash);

#endif