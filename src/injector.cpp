#include <Windows.h>
#include <filesystem>
#include <string>
#include "Logger.h"
#include "injector.h"

bool inject(HANDLE target, const char *path) {
    LPVOID loadlib = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

    LPVOID dllPathAddr = VirtualAllocEx(target, NULL, strlen(path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
        ERR("Failed allocating memory in the target process. GetLastError(): %s\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(target, dllPathAddr, path, strlen(path) + 1, NULL)) {
        ERR("Failed writing to process. GetLastError(): %s\n", GetLastError());
        return false;
    }

    HANDLE hThread = CreateRemoteThread(target, NULL, NULL, (LPTHREAD_START_ROUTINE) loadlib, dllPathAddr, NULL, NULL);
    if (hThread == NULL) {
        ERR("Failed to create a thread in the target process. GetLastError(): %s\n", GetLastError());
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    VirtualFreeEx(target, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    if (exit_code == 0) {
        ERR("LoadLibrary failed.\n");
        return false;
    }
    SUC("We are injected :)\n");
    return true;
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

extern "C" __declspec(dllexport) void inject_into(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {

    INIT_LOGGER("CrackPipe", RGB(74, 255, 155), RGB(35, 173, 252), RGB(252, 35, 60), RGB(71, 245, 103));
    if (!IsElevated()) {
        ERR("You need to run this as admin!\n");
        system("pause");
        return;
    }
    char our_dll[260];
    HMODULE hm = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&inject_into), &hm);
    GetModuleFileNameA(hm, our_dll, 260);
    SUC("Running as an injector ;)\n");

    std::filesystem::path target = std::filesystem::path(lpszCmdLine);
    std::filesystem::path dll = std::filesystem::path(our_dll);
    PROCESS_INFORMATION pi{};
    STARTUPINFOA si{};

    if (target.string().ends_with("korepi.exe")) {
        SHELLEXECUTEINFOA shExecInfo = {0};
        shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
        shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shExecInfo.lpFile = std::filesystem::absolute(target).string().c_str();
        shExecInfo.lpDirectory = std::filesystem::absolute(target).parent_path().string().c_str();
        shExecInfo.nShow = SW_SHOWNORMAL;
        HANDLE hToken;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
                         &hToken);
        DBG("target: %s, dir: %s\n", shExecInfo.lpFile, shExecInfo.lpDirectory);
        if (!CreateProcessAsUserA(hToken, std::filesystem::absolute(target).string().c_str(), nullptr, NULL, NULL,
                                  FALSE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL,
                                  target.parent_path().string().c_str(), &si, &pi)) {
            ERR("Failed to start korepi.exe\n");
        } else {
            inject(pi.hProcess, std::filesystem::absolute(dll).string().c_str());
            Sleep(500);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
//            minty_inject(shExecInfo.hProcess, std::filesystem::absolute(dll).string().c_str());
//            CloseHandle(shExecInfo.hProcess);
        }
        return;
    }


    if (!CreateProcessA(target.string().c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                        target.parent_path().string().c_str(), &si, &pi)) {
        ERR("Failed to start target process\n");
    } else {

        inject(pi.hProcess, std::filesystem::absolute(dll).string().c_str());
        Sleep(500);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}