// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#define COBJMACROS

#include <metahost.h>
#include <combaseapi.h>


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		OutputDebugStringW(L"[PSINJECT] In Bootstrap Process Attach");
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		break;
    }
    return TRUE;
}


DWORD StartCLR(const WCHAR* managedDllLocation, LPCWSTR dotNetVersion);

__declspec(dllexport) DWORD runme(const WCHAR* managedDllLocation)
{
	DWORD ret = 0;

	static WCHAR printMe[1000] = L"[PSINJECT] In Bootstrap Func: ";

	wcscat_s(printMe, 1000, managedDllLocation);
	OutputDebugStringW(printMe);

	// Secure a handle to the CLR v4.0
	// TODO, could also use "EnumerateInstalledRuntimes" and just find the latest installed version 
	ret = StartCLR(managedDllLocation, L"v4.0.30319");

	return ret;
}

DWORD StartCLR(const WCHAR* managedDllLocation, LPCWSTR dotNetVersion)
{
	DWORD ret = 0;
	HRESULT hr;

	ICLRMetaHost* pClrMetaHost = NULL;
	ICLRRuntimeInfo* pClrRuntimeInfo = NULL;
	ICLRRuntimeHost* pClrRuntimeHost = NULL;

	// Get the CLRMetaHost that tells us about .NET on this machine
	hr = CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID*)&pClrMetaHost);
	if (hr == S_OK)
	{
		// Get the runtime information for the particular version of .NET
		hr = ICLRMetaHost_GetRuntime(pClrMetaHost, dotNetVersion, &IID_ICLRRuntimeInfo, &pClrRuntimeInfo);
		if (hr == S_OK)
		{
			// Check if the specified runtime can be loaded into the process. This
			// method will take into account other runtimes that may already be
			// loaded into the process and set pbLoadable to TRUE if this runtime can
			// be loaded in an in-process side-by-side fashion.
			BOOL fLoadable;
			hr = ICLRRuntimeInfo_IsLoadable(pClrRuntimeInfo, &fLoadable);
			if ((hr == S_OK) && fLoadable)
			{
				// Load the CLR into the current process and return a runtime interface
				// pointer.
				hr = ICLRRuntimeInfo_GetInterface(pClrRuntimeInfo, &CLSID_CLRRuntimeHost,
					&IID_ICLRRuntimeHost, &pClrRuntimeHost);
				if (hr == S_OK)
				{
					// Start it. This is okay to call even if the CLR is already running
					ICLRRuntimeHost_Start(pClrRuntimeHost);

					// Call the Stuff
					DWORD result = 0;
					hr = ICLRRuntimeHost_ExecuteInDefaultAppDomain(pClrRuntimeHost,
						managedDllLocation,
						L"Injected.Injected",
						L"EntryPoint",
						L"Argument",
						&result);
					if (hr != S_OK || 0 != result)
					{
						OutputDebugStringW(L"[PSINJECT] DotNet Func Failure");
					}

					// Stop everything and shut it down?
					ICLRRuntimeHost_Stop(pClrRuntimeHost);
				}
			}
		}
	}

	// Cleanup
	if (NULL != pClrRuntimeHost)
	{
		ICLRRuntimeHost_Release(pClrRuntimeHost);
		pClrRuntimeHost = NULL;
	}
	if (NULL != pClrRuntimeInfo)
	{
		ICLRRuntimeInfo_Release(pClrRuntimeInfo);
		pClrRuntimeInfo = NULL;
	}
	if (NULL != pClrMetaHost)
	{
		ICLRMetaHost_Release(pClrMetaHost);
		pClrMetaHost = NULL;
	}

	return ret;
}
