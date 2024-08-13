//
// Created by vesel on 12.08.2024.
//

#ifndef LOL_UTIL_H
#define LOL_UTIL_H

#include <Windows.h>
#include "hde/hde64.h"
#include <vector>
#include "Logger.h"
#include "MinHook.h"

bool bypass_vmp() {
    const auto ntdll = GetModuleHandle(L"ntdll.dll");
    uint8_t callcode = ((uint8_t *) GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
    uint8_t restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};
    volatile auto ntProtectVirtualMemory = (uint8_t *) GetProcAddress(ntdll, "NtProtectVirtualMemory");
    while (true) {
        if (ntProtectVirtualMemory[0] != 0x4C) {
            DWORD oldProtect;
            VirtualProtect((LPVOID) ntProtectVirtualMemory, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(ntProtectVirtualMemory, restore, sizeof(restore));
            VirtualProtect((LPVOID) ntProtectVirtualMemory, sizeof(restore), oldProtect, nullptr);
            LOG("Bypassed VMP\n");
            return true;
        } else {
            LOG("Nothing seems to be hooking NtProtectVirtualMemory\n");
            return false;
        }
    }
}

uintptr_t scan_manual(uint8_t *start, unsigned long size_of_image, const char *pattern) {
    static auto pattern_to_byte = [](const char *pattern) {

        auto bytes = std::vector<int>{};

        const auto start = const_cast<char *>(pattern);

        const auto end = const_cast<char *>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            } else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    const auto pattern_bytes = pattern_to_byte(pattern);
    auto scan_bytes = start;
    const auto s = pattern_bytes.size();
    const auto d = pattern_bytes.data();

    for (auto i = 0ul; i < size_of_image - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scan_bytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }

        if (found) {
            return reinterpret_cast<uintptr_t>(&scan_bytes[i]);
        }
    }
    return 0;
}
void replace_all(
        std::string &s,
        std::string const &toReplace,
        std::string const &replaceWith
) {
    std::string buf;
    std::size_t pos = 0;
    std::size_t prevPos;

    // Reserves rough estimate of final size of string.
    buf.reserve(s.size());

    while (true) {
        prevPos = pos;
        pos = s.find(toReplace, pos);
        if (pos == std::string::npos)
            break;
        buf.append(s, prevPos, pos - prevPos);
        buf += replaceWith;
        pos += toReplace.size();
    }

    buf.append(s, prevPos, s.size() - prevPos);
    s.swap(buf);
}

uintptr_t scan(const char *module, const char *pattern) {

    const auto mod = GetModuleHandleA(module);
    if (!mod)
        return 0;

    const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t *>(mod) +
                                                                dos_header->e_lfanew);
    return scan_manual(reinterpret_cast<uint8_t *>(mod), nt_headers->OptionalHeader.SizeOfImage, pattern);
}

void remove_hooks() {
    bypass_vmp();
    MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
    if (status == MH_OK)
        SUC("Disabled all hooks\n");
    else
        ERR("Something went wrong while disabling hooks: %s\n", MH_StatusToString(status));
    status = MH_RemoveHook(MH_ALL_HOOKS);
    if (status == MH_OK)
        SUC("Removed all hooks\n");
    else if (status == MH_ERROR_NOT_CREATED)
        SUC("No hooks to remove.\n");
    else
        ERR("Something went wrong while removing hooks: %s\n", MH_StatusToString(status));
    status = MH_Uninitialize();
    if (status == MH_OK)
        SUC("MinHook un-initialized\n");
    else
        ERR("Something went wrong while un-initializing MinHook: %s\n", MH_StatusToString(status));
    for (auto &veh_hook: VehUtils::veh_hooks) {
        veh_hook.disable();
    }
    SUC("Removed all VEH hooks.\n");
    g_vehUtils.~VehUtils();
}

void unhook_and_leave_thread() {

    remove_hooks();

    LOG("Freeing library and exiting thread! Goodbye~\n");
    HMODULE hm;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&unhook_and_leave_thread), &hm);
    FreeLibraryAndExitThread(hm, 0);
}

void unhook_and_leave() {
//    MH_RemoveHook(MH_ALL_HOOKS);
    auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE) unhook_and_leave_thread, nullptr, 0, nullptr);
    CloseHandle(thread);
}

#endif //LOL_UTIL_H
