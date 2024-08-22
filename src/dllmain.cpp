//
// Created by vesel on 22.08.2024.
//
#include <experimental/string>
#include "dllmain.h"

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, const char *data) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
//        std::string krpi_base = std::string(korepibase);
//        MessageBoxA(nullptr, korepibase, "jell", 1);
        StartupData *startupData;
        startupData = (StartupData *) malloc(sizeof(StartupData));
        startupData->korepibase = nullptr;
        if (data != nullptr) {
            std::string d = std::string(data);
            size_t split = d.find(';', 0);
            std::string korepibase = d.substr(0, split);
            std::string self_path = d.substr(split + 1, d.length());
            startupData->korepibase = (char *) malloc(korepibase.length() + 1);
            memcpy(startupData->korepibase, korepibase.data(), korepibase.length() + 1);

            startupData->path = (char *) malloc(self_path.length() + 1);
            memcpy(startupData->path, self_path.data(), self_path.length() + 1);

        }
        startupData->pBase = hinstDLL;
        const auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE) start, startupData, 0, nullptr);
        DisableThreadLibraryCalls(hinstDLL);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return true;
}
