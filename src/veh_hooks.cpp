//
// Created by vesel on 06.08.2024.
//

#include "veh_hooks.h"

LONG WINAPI VehUtils::VEH(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        auto hook = std::find(VehUtils::veh_hooks.begin(), VehUtils::veh_hooks.end(),
                              ExceptionInfo->ExceptionRecord->ExceptionAddress);
        if (hook != VehUtils::veh_hooks.end() && hook->isEnabled()) {
            if (!hook->origCalled()) {
                DBG("Calling vehhook!\n");
                ExceptionInfo->ContextRecord->Rip = (DWORD64) hook->getHookAddr();
            }
        }
        ExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    } else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        for (auto &veh_hook: VehUtils::veh_hooks) {
            veh_hook.protect();
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    } else if (std::find(VehUtils::bypass_addrs.begin(), VehUtils::bypass_addrs.end(),
                         ExceptionInfo->ExceptionRecord->ExceptionAddress) !=
               VehUtils::bypass_addrs.end()) {
        DBG("Bypass crc~\n");
        ExceptionInfo->ContextRecord->Rip += 0x2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
