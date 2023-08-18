// dll injec osclient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

int injectDll(const wchar_t* exeName, const char* dllPath)
{
    HANDLE hSnap;
    PROCESSENTRY32 pe;
    HANDLE hProcess;
    LPVOID pRemoteBuf;
    SIZE_T dwBufSize = strlen(dllPath) + 1;
    SIZE_T dwNumBytesWritten;
    HMODULE hMod;

    
    BOOL bOk;

    // Take a snapshot of all processes in the system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot() failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Initialize the process entry structure
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
    if (!Process32First(hSnap, &pe)) {
        std::cerr << "Process32First() failed: " << GetLastError() << std::endl;
        CloseHandle(hSnap);
        return 1;
    }

    // Find the process with the matching name
    while (_tcsicmp(pe.szExeFile, exeName) != 0) {
        if (!Process32Next(hSnap, &pe)) {
            std::cerr << "Process32Next() failed: " << GetLastError() << std::endl;
            CloseHandle(hSnap);
            return 1;
        }
    }

    // Get a handle to the process
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pe.th32ProcessID);
    if (!hProcess) {
        std::cerr << "OpenProcess() failed: " << GetLastError() << std::endl;
        CloseHandle(hSnap);
        return 1;
    }

    // Allocate memory in the process's address space for the DLL path
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::cerr << "VirtualAllocEx() failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hSnap);
        return 1;
    }

    // Write the DLL path to the process's memory
    bOk = WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, dwBufSize, &dwNumBytesWritten);
    if (!bOk || dwNumBytesWritten != dwBufSize) {
        std::cerr << "WriteProcessMemory() failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(hSnap);
        return 1;
    }

    // Get the address of LoadLibraryA function in kernel32.dll
    hMod = GetModuleHandle(_T("kernel32.dll"));
    if (!hMod) {
        std::cerr << "GetModuleHandle() failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(hSnap);
        return 1;
    }


        // Get the address of the LoadLibraryA function
    LPVOID lpStartAddress = GetProcAddress(hMod, "LoadLibraryA");
    if (!lpStartAddress) {
        std::cerr << "Failed to get the address of LoadLibraryA" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory for the DLL path in the target process
    LPVOID lpRemoteString = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteString) {
        std::cerr << "Failed to allocate memory in target process" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, lpRemoteString, (LPVOID)dllPath, dwBufSize, NULL)) {
        std::cerr << "Failed to write DLL path into target process" << std::endl;
        VirtualFreeEx(hProcess, lpRemoteString, dwBufSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpRemoteString, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, lpRemoteString, dwBufSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
        std::cerr << "Failed to wait for remote thread" << std::endl;
        VirtualFreeEx(hProcess, lpRemoteString, dwBufSize, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Free the memory in the target process and clean up handles
    VirtualFreeEx(hProcess, lpRemoteString, dwBufSize, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}
int main()
{
    injectDll(L"osclient.exe", "C:\\Users\\s four mmie\\source\\repos\\victimScape\\x64\\Debug\\victimScape.dll");
    return 0;
}
