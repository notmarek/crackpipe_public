//
// Created by vesel on 06.08.2024.
//

#ifndef LOL_VEH_HOOKS_H
#define LOL_VEH_HOOKS_H

#include <vector>
#include <Windows.h>
#include <algorithm>
#include "Logger.h"

class VehHook {
public:
    VehHook(void *original_addr, void *hook_addr) {
        this->og_addr = original_addr;
        this->hook_addr = hook_addr;
    }

    bool enable() {
        this->enabled = true;
        bool result = this->protect();
        return result;
    }

    bool disable() {
        this->enabled = false;
        bool result = this->unprotect();
        return result;
    }

    bool isEnabled() const {
        return this->enabled;
    }

    void *getHookAddr() {
        return this->hook_addr;
    }

    void callOrig() {
        this->call_orig = true;
    }

    bool origCalled() {
        if (this->call_orig) {
            this->call_orig = false;
            return true;
        }
        return false;
    }

    bool protect() {
        DWORD oldProt;
        if (this->isEnabled())
            return VirtualProtect(this->og_addr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProt);
        return false;
    }

    bool unprotect() {
        DWORD oldProt;
        if (!this->isEnabled())
            return VirtualProtect(this->og_addr, 1, PAGE_EXECUTE_READ, &oldProt);
        return false;
    }

    bool operator==(void *rhs) {
        return this->og_addr == rhs;
    }

    void *og_addr;
    void *hook_addr;
    bool enabled{};
    bool call_orig{};
};


class VehUtils {
public:

    static void addBypass(void *addr) {
        bypass_addrs.push_back(addr);
    }

    static void addHook(VehHook hook) {
        veh_hooks.push_back(hook);
    }

    ~VehUtils() {
        RemoveVectoredExceptionHandler(this->handler);
    }

    void Init() {
        this->handler = AddVectoredExceptionHandler(true, VEH);
    }

    void *handler;
    inline static std::vector<VehHook> veh_hooks;

    static LONG WINAPI VEH(EXCEPTION_POINTERS *ExceptionInfo);

    inline static std::vector<void *> bypass_addrs;
};

inline VehUtils g_vehUtils;
#endif //LOL_VEH_HOOKS_H
