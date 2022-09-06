#ifndef _INCLUDES_H
#define _INCLUDES_H

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _CLIENT_ID {
    DWORD64 UniqueProcess;
    DWORD64 UniqueThread;

} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STR ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
(p)->RootDirectory = r;                           \
(p)->Attributes = a;                              \
(p)->ObjectName = n;                              \
(p)->SecurityDescriptor = s;                      \
(p)->SecurityQualityOfService = NULL;             \
}
#endif
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

#endif