#ifndef INCLUDES_H
#define INCLUDES_H

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

typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    Spare3 = 22,
    Spare4 = 23,
    Spare5 = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct {
   LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} _SYSTEM_THREAD_INFORMATION, * _PSYSTEM_THREAD_INFORMATION;

typedef LONG       KPRIORITY;

typedef struct _VM_COUNTERS {
    SIZE_T		   PeakVirtualSize;
    SIZE_T         PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         VirtualSize;
} VM_COUNTERS;

typedef struct {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    FILETIME CreateTime;
    FILETIME UserTime;
    FILETIME KernelTime;
    UNICODE_STR ImageName;
    KPRIORITY BasePriority;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG ProcessId;
#ifdef _WIN64
    ULONG pad2;
#endif
    ULONG InheritedFromProcessId;
#ifdef _WIN64
    ULONG pad3;
#endif
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    VM_COUNTERS VirtualMemoryCounters;
    ULONG_PTR PrivatePageCount;
    IO_COUNTERS IoCounters;
    _SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} _SYSTEM_PROCESS_INFORMATION, * _PSYSTEM_PROCESS_INFORMATION;

#endif