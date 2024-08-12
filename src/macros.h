//
// Created by vesel on 03.08.2024.
//

#ifndef LOL_MACROS_H
#define LOL_MACROS_H

#include "veh_hooks.h"

#define TRAD_ORIG(fn) static_cast<decltype(&(fn))>(o_##fn)
#define VEH_ORIG(fn, ...) ([=]() { \
    auto vehhook = std::find(VehUtils::veh_hooks.begin(), VehUtils::veh_hooks.end(), (void*)o_##fn);\
    vehhook->callOrig();  \
    return TRAD_ORIG(fn)(__VA_ARGS__);    \
})()

#define IS_VEH_HOOK(ptr) std::find(VehUtils::veh_hooks.begin(), VehUtils::veh_hooks.end(), (void*)ptr) != VehUtils::veh_hooks.end()

#define ORIG(fn, ...) ([=]() {\
if (IS_VEH_HOOK(o_##fn)) { \
    return VEH_ORIG(fn, __VA_ARGS__); } \
else { \
    return TRAD_ORIG(fn)(__VA_ARGS__); } \
})()

#define SCAN_MANUAL_WHILE_LIMIT_OR_FOUND(buf, size, pat) \
    void *found = (void *) scan_manual(buf, size, pat); \
    while (found == nullptr && i < LIMIT) { \
        found = (void *) scan_manual(buf, size, pat); \
        Sleep(500); \
        i++; \
    }

#define SCAN_WHILE_LIMIT_OR_FOUND(module, pat) \
    void *found = (void *) scan(module, pat); \
    while (found == nullptr && i < LIMIT) { \
        found = (void *) scan(module, pat); \
        Sleep(500); \
        i++; \
    }

#define VEH_HOOK_IF_FOUND_AND(module, name, pat, func) \
    if (GetModuleHandleA(module) != nullptr) {         \
    LOG("Scanning for %s inside %s\n", name, module);   \
    SCAN_WHILE_LIMIT_OR_FOUND(module, pat);            \
    if (found != nullptr) {                            \
        SUC("Found %s @ %p -> %p\n", name, found, (void*)func);           \
        auto hk = VehHook(found, (void*)func);         \
        o_##func = found;\
                           \
        if(hk.enable()) { \
            SUC("Created %s VEH hook @ %p\n", name, found);               \
          VehUtils::addHook(hk);  \
        } else { \
            ERR("VirtualProtect failed!"); \
        }                                              \
        \

#define VEH_HOOK_IF_FOUND(module, name, pat, func) \
        VEH_HOOK_IF_FOUND_AND(module, name, pat, func) \
        }                                         \
        i = 0;                                     \
    }
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOOK_IF_FOUND_MANUAL_AND(buf, size, name, pat, func) \
        LOG("Scanning for %s inside %p-%p\n", name, buf, buf+size); \
        {                                                             \
        SCAN_MANUAL_WHILE_LIMIT_OR_FOUND(buf, size, pat) \
        if (found != nullptr) { \
            VehUtils::addBypass(found);\
            SUC("Found %s @ %p\n", name, found); \
            MH_STATUS result = MH_CreateHook((LPVOID) found, (void *) func, (LPVOID *) &o_##func); \
            if (result == MH_OK) SUC("Created %s hook @ %p\n", name, found); \
            else ERR("MH_CreateHook failed: %s\n", MH_StatusToString(result)); \
            result = MH_EnableHook((LPVOID) found); \
            if (result == MH_OK) SUC("Enabled %s hook\n", name, found); \
            else ERR("MH_EnableHook failed: %s\n", MH_StatusToString(result)); \


#define HOOK_IF_FOUND_MANUAL(buf, size, name, pat, func) \
    HOOK_IF_FOUND_MANUAL_AND(buf, size, name, pat, func) \
                                                             \
 }  else DBG("Couldn't find %s\n", name);                \
 i=0;}\


#define HOOK_IF_FOUND_AND(module, name, pat, func) \
    if (GetModuleHandleA(module) != nullptr) { \
        LOG("Scanning for %s inside %s\n", name, module); \
        SCAN_WHILE_LIMIT_OR_FOUND(module, pat) \
        if (found != nullptr) { \
            VehUtils::addBypass(found);\
            SUC("Found %s @ %p\n", name, found); \
            MH_STATUS result = MH_CreateHook((LPVOID) found, (void *) func, (LPVOID *) &o_##func); \
            if (result == MH_OK) SUC("Created %s hook @ %p\n", name, found); \
            else ERR("MH_CreateHook failed: %s\n", MH_StatusToString(result)); \
            result = MH_EnableHook((LPVOID) found); \
            if (result == MH_OK) SUC("Enabled %s hook\n", name, found); \
            else ERR("MH_EnableHook failed: %s\n", MH_StatusToString(result)); \


#define HOOK_IF_FOUND(module, name, pat, func) \
    HOOK_IF_FOUND_AND(module, name, pat, func) \
 }  else DBG("Couldn't find %s\n", name); \
i = 0;                                         \
}
#define API_HOOK(dll, proc, func) o_##func = hook_exported(dll, proc, func)
#endif //LOL_MACROS_H
