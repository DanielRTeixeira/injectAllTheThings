#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

VOID displayHelp()
{
	wprintf(TEXT("injectAllTheThings - rui@deniable.org\n"));
	wprintf(TEXT("Usage: injectAllTheThings.exe -t <option> <process name> <path/to/dll>\n"));
	wprintf(TEXT("Options:\n"));
	wprintf(TEXT("  1\tDLL injection via CreateRemoteThread()\n"));
	wprintf(TEXT("  2\tDLL injection via NtCreateThreadEx()\n"));
	wprintf(TEXT("  3\tDLL injection via QueueUserAPC()\n"));
	wprintf(TEXT("  4\tDLL injection via SetWindowsHookEx()\n"));
	wprintf(TEXT("  5\tDLL injection via RtlCreateUserThread()\n"));
	wprintf(TEXT("  6\tDLL injection via Code Cave SetThreadContext()\n"));
	wprintf(TEXT("  7\tReflective DLL injection\n"));
}

DWORD findPidByName(wchar_t * pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!_wcsicmp(procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
#ifdef _DEBUG
			wprintf(TEXT("[+] PID found: %ld\n"), pid);
#endif
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

DWORD checkOS() 
{
	OSVERSIONINFO os_version;

	os_version.dwOSVersionInfoSize = sizeof(os_version);

	if (GetVersionEx(&os_version)) 
	{
		if (os_version.dwMajorVersion == 5) 
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows XP\n"));
#endif
			return(1);
		}
		if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 0) 
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows Vista\n"));
#endif
			return(2);
		}
		if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 1)
		{
#ifdef _DEBUG
			wprintf(TEXT("[+] OS version: Windows 7\n"));
#endif
			return(3);
		}
	}
	else
		printf("[-] OS version detect failed.\n");

	return(0);
}

DWORD getThreadID(DWORD pid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
							wprintf(TEXT("[-] Error: Couldn't get thread handle\n"));
						else
							return te.th32ThreadID;
					}
				}
			} while (Thread32Next(h, &te));
		}
	}

	CloseHandle(h);
	return (DWORD)0;
}