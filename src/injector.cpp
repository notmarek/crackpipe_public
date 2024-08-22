#include <Windows.h>
#include <filesystem>
#include <string>
#include "Logger.h"
#include "injector.h"
#include "korepi_injector/manual_map.h"
#include "korepi_injector/korepi_injector.h"
#include "dllmain.h"

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

int main(int argc, char *argv[]) {

    INIT_LOGGER("CrackPipe", RGB(74, 255, 155), RGB(35, 173, 252), RGB(252, 35, 60), RGB(71, 245, 103));
    if (!IsElevated()) {
        ERR("You need to run this as admin!\n");
        system("pause");
        return 1;
    }
    if (argc < 2) {
        ERR("Not enough arguments\n");
        system("pause");
        return 1;
    }
    HMODULE base = GetModuleHandleA(nullptr);
    LOG("base: %p\n", base);

    void *entrypoint = (void *) ((uint64_t) DllMain - (uint64_t) base);
    LOG("EntryPoint offset: %p\n", entrypoint);
    if (std::string(argv[1]).ends_with(".dll")) {
        return inject_korepi(argc, argv, entrypoint);
    }
    LOG("We are not injecting korepi");
    char our_dll[260];

    GetModuleFileNameA(base, our_dll, 260);
    SUC("Running as an injector ;)\n");

    std::filesystem::path target = std::filesystem::path(argv[1]);
    std::filesystem::path dll = std::filesystem::path(our_dll);
    PROCESS_INFORMATION pi{};
    STARTUPINFOA si{};

    if (target.string().ends_with("korepi.exe") || target.string().ends_with("AkebiLauncher.exe")) {
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
        return 0;
    }


    if (!CreateProcessA(target.string().c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                        target.parent_path().string().c_str(), &si, &pi)) {
        ERR("Failed to start target process\n");
    } else {

        ManualMapDLL_(pi.hProcess, std::filesystem::absolute(dll).string(),
                      std::format(";{}", std::filesystem::absolute(dll).string()), entrypoint);
//        inject(pi.hProcess, std::filesystem::absolute(dll).string().c_str());
        Sleep(500);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return 0;
}