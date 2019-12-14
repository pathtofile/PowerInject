// powerinjectRunner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>
#include <tlhelp32.h>


#define BOOT_DLL_NAME L"bootstrap.dll"
#define SHARP_DLL_NAME L"injected.dll"
#define BOOT_FUNC "runme"

static WCHAR BOOTDLLPATH[MAX_PATH] = { 0 };


typedef DWORD(WINAPI* BootFunc)(const WCHAR*);

INT injectSelf()
{
	INT ret = 0;
	HANDLE hBootLocal = LoadLibrary(BOOT_DLL_NAME);
	if (NULL == hBootLocal)
	{
		printf("Failed to load Bootstrap DLL locally\n");
		ret = 3;
	}
	else
	{
		BootFunc fnBootFunc = (BootFunc)GetProcAddress(hBootLocal, BOOT_FUNC);

		ret = fnBootFunc(L"injected.dll");
	}

	return ret;
}


INT
callExport
(
	DWORD pid,
	HMODULE hProc
)
{
	INT		ret = 0;
	HANDLE	hProcSnap = NULL;
	HANDLE	hBootLocal = NULL;
	HANDLE	hThreadBootFunc = NULL;

	// Get Full path to the C# DLL to run inside the project
	// we will pass this in as an argument to the function
	WCHAR dotnetPath[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, dotnetPath, MAX_PATH);
	PathRemoveFileSpecW(dotnetPath);
	wcscat_s(dotnetPath, MAX_PATH, L"\\");
	wcscat_s(dotnetPath, MAX_PATH, SHARP_DLL_NAME);

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hProcSnap == INVALID_HANDLE_VALUE)
	{
		printf("Failed to get snapshot of PID: %d\n", pid);
		ret = 1;
		goto cleanup;
	}

	// Get the ModuleEntry structure of the desired library
	MODULEENTRY32W ModEntry = { sizeof(ModEntry) };
	BOOL foundDLL = FALSE;
	BOOL bMoreMods = Module32FirstW(hProcSnap, &ModEntry);
	for (; bMoreMods; bMoreMods = Module32NextW(hProcSnap, &ModEntry))
	{
		// Check Exe matched
		if (0 == lstrcmpiW(ModEntry.szExePath, BOOTDLLPATH))
		{
			foundDLL = TRUE;
			break;
		}
	}
	if (!foundDLL)
	{
		printf("Failed to find Bootstrap in process of PID: %d\n", pid);
		ret = 2;
		goto cleanup;
	}

	// Get module base address
	PBYTE ModuleBase = ModEntry.modBaseAddr;
	hBootLocal = LoadLibraryExW(BOOTDLLPATH, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (NULL == hBootLocal)
	{
		printf("Failed to load Bootstrap DLL locally\n");
		ret = 3;
		goto cleanup;
	}
	PBYTE pBoot = hBootLocal;

	// INSTEAD of all the DLL walking, just call GetProcAddress????
	LPTHREAD_START_ROUTINE fnLocalBootFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(hBootLocal, BOOT_FUNC);
	//// Walk the headers
	//PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hBootLocal;
	//if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic)
	//{
	//	printf("Invalid PE header in local Bootstrap DLL\n");
	//	ret = 4;
	//	goto cleanup;
	//}
	//PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pBoot + pDosHeader->e_lfanew);
	//if (IMAGE_NT_SIGNATURE != pNtHeader->Signature)
	//{
	//	printf("Invalid NT Sig in local Bootstrap DLL\n");
	//	ret = 5;
	//	goto cleanup;
	//}
	//PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBoot + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	//if (0 == pExportDir->AddressOfNames)
	//{
	//	printf("Missing Symbol Names in local Bootstrap DLL\n");
	//	ret = 6;
	//	goto cleanup;
	//}
	//PDWORD pNamesRvas = (PDWORD)(pBoot + pExportDir->AddressOfNames);
	//PDWORD pNameOrdinals = (PDWORD)(pBoot + pExportDir->AddressOfNameOrdinals);
	//PDWORD pFunctionAddresses = (PDWORD)(pBoot + pExportDir->AddressOfFunctions);
	//// Variable to hold the export address
	//// Walk the array of this module's function names
	//// To find the Function
	//FARPROC fnLocalBootFunc = NULL;
	//for (DWORD n = 0; n < pExportDir->NumberOfNames; n++)
	//{
	//	// Get the function name
	//	PCHAR funcName = (PCHAR)(pBoot + pNamesRvas[n]);
	//	if (0 != lstrcmpiA(funcName, BOOT_FUNC))
	//	{
	//		continue;
	//	}
	//	else
	//	{
	//		// Found the function
	//		WORD funcOrdinal = (WORD)pNameOrdinals[n];
	//		fnLocalBootFunc = (FARPROC)(pBoot + pFunctionAddresses[funcOrdinal]);
	//		break;
	//	}
	//}
	//if (NULL == fnLocalBootFunc)
	//{
	//	printf("Didn't Find Func '%s' in Bootstrap DLL\n", BOOT_FUNC);
	//	ret = 7;
	//	goto cleanup;
	//}

	// Convert from local address to remote??
	LPTHREAD_START_ROUTINE fnRemoteBootFunc = (LPTHREAD_START_ROUTINE)((PBYTE)fnLocalBootFunc - pBoot + ModuleBase);
	if (NULL == fnRemoteBootFunc)
	{
		printf("Failed to find remote Bootstrap Function in PID: %d\n", pid);
		ret = 8;
		goto cleanup;
	}

	// Copy the string argument over to the remote process
	SIZE_T dotnetPathSize = wcslen(dotnetPath) * sizeof(WCHAR);
	LPVOID pRemoteDotnetPath = (LPVOID)VirtualAllocEx(hProc, NULL, dotnetPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pRemoteDotnetPath)
	{
		printf("Failed allocate memory for Dotnet DLL Path in PID: %d\n", pid);
		ret = 9;
		goto cleanup;
	}
	if (!WriteProcessMemory(hProc, pRemoteDotnetPath, dotnetPath, dotnetPathSize, NULL))
	{
		printf("Failed to write Dotnet DLL path into in PID: %d\n", pid);
		ret = 10;
		goto cleanup;
	};

	hThreadBootFunc = CreateRemoteThread(hProc, NULL, 0, fnRemoteBootFunc, pRemoteDotnetPath, 0, NULL);
	if (NULL == hThreadBootFunc)
	{
		printf("Failed Start Bootstrap Function thread in PID: %d\n", pid);
		ret = 11;
		goto cleanup;
	}
	WaitForSingleObject(hThreadBootFunc, INFINITE);

	DWORD remoteFuncRet = 0;
	GetExitCodeThread(hThreadBootFunc, &remoteFuncRet);
	if (0 != remoteFuncRet)
	{
		printf("Bootstrap Function thread failed in PID: %d with error: %d\n", pid, remoteFuncRet);
		ret = 12;
		goto cleanup;
	}

	// Free remote string
	VirtualFreeEx(hProc, pRemoteDotnetPath, 0, MEM_RELEASE);


cleanup:
	if (NULL != hThreadBootFunc)
	{
		CloseHandle(hThreadBootFunc);
	}
	if (NULL != hBootLocal)
	{
		FreeLibrary(hBootLocal);
	}
	if (NULL != hProcSnap)
	{
		CloseHandle(hProcSnap);
	}
	return ret;
}

INT injectPid(DWORD pid)
{
	INT		ret = 0;
	HMODULE hKernel32 = NULL;
	HMODULE hProc = NULL;
	HANDLE	hThreadLL = NULL;
	HANDLE	hThreadFL = NULL;

	// Get Full path to the bootstrap DLL to inject into process
	GetModuleFileNameW(NULL, BOOTDLLPATH, MAX_PATH);
	PathRemoveFileSpecW(BOOTDLLPATH);
	wcscat_s(BOOTDLLPATH, MAX_PATH, L"\\");
	wcscat_s(BOOTDLLPATH, MAX_PATH, BOOT_DLL_NAME);

	// Get handle to kernel32
	hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (NULL == hKernel32)
	{
		printf("Failed to get handle to kernel32\n");
		ret = 2;
		goto cleanup;
	}

	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProc)
	{
		printf("Failed to get handle to Process PID: %d\n", pid);
		ret = 3;
		goto cleanup;
	}

	// Allocate string to pass into LoadLibraryA
	SIZE_T booDllPathSize = wcslen(BOOTDLLPATH) * sizeof(WCHAR);
	LPVOID pRemoteBootPath = (LPVOID)VirtualAllocEx(hProc, NULL, booDllPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pRemoteBootPath)
	{
		printf("Failed allocate memory in PID: %d\n", pid);
		ret = 4;
		goto cleanup;
	}
	if (!WriteProcessMemory(hProc, pRemoteBootPath, BOOTDLLPATH, booDllPathSize, NULL))
	{
		printf("Failed to write bootstrap path into in PID: %d\n", pid);
		ret = 4;
		goto cleanup;
	};

	// Start a remote thread on the targeted Process, to call LoadLibraryA(bootstrap_dll)
	LPTHREAD_START_ROUTINE fnLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	hThreadLL = CreateRemoteThread(hProc, NULL, 0, fnLoadLibrary, pRemoteBootPath, 0, NULL);
	if (NULL == hThreadLL)
	{
		printf("Failed Start LoadLibrary thread in PID: %d\n", pid);
		ret = 5;
		goto cleanup;
	}
	WaitForSingleObject(hThreadLL, INFINITE);

	HMODULE hBootRemote = NULL;
	GetExitCodeThread(hThreadLL, (DWORD*)&hBootRemote);
	if (NULL == hBootRemote)
	{
		printf("Failed Load Bootstrap DLL into PID: %d\n", pid);
		ret = 6;
		goto cleanup;
	}

	// Free remote string
	VirtualFreeEx(hProc, pRemoteBootPath, 0, MEM_RELEASE);

	// Call Bootstrap function
	ret = callExport(pid, hProc);
	if (ret != 0)
	{
		printf("Failed callExport: %d\n", ret);
		ret = 7;
		goto cleanup;
	}

	// Unload module
	LPTHREAD_START_ROUTINE fnFreeLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary");
	hThreadFL = CreateRemoteThread(hProc, NULL, 0, fnFreeLibrary, hBootRemote, 0, NULL);
	if (NULL == hThreadFL)
	{
		printf("Failed Start FreeLibrary thread in PID: %d\n", pid);
		ret = 8;
		goto cleanup;
	}
	WaitForSingleObject(hThreadFL, INFINITE);

	DWORD freeRet = 0;
	GetExitCodeThread(hThreadFL, &freeRet);
	if (freeRet == 0)
	{
		printf("Failed Call FreeLibrary thread in PID: %d\n", pid);
		ret = 8;
		goto cleanup;
	}

cleanup:
	if (NULL != hThreadFL)
	{
		CloseHandle(hThreadFL);
	}
	if (NULL != hThreadLL)
	{
		CloseHandle(hThreadLL);
	}
	if (NULL != hProc)
	{
		CloseHandle(hProc);
	}
	return ret;
}

INT main(int argc, char** argv)
{
	INT		ret = 0;
	DWORD	pid = 0;

	if (1 == argc)
	{
		printf("Injecting into self\n");
		ret = injectSelf();
	}
	else if(2 == argc)
	{
		pid = atoi(argv[1]);
		if (0 >= pid || INT_MAX == pid)
		{
			printf("Usage: %s <pid_to_inject>\n", argv[0]);
			ret = 1;
		}
		ret = injectPid(pid);
	}
	else
	{
		printf("Usage: %s <pid_to_inject>\n", argv[0]);
		ret = 1;
	}

	return ret;
}
