//
// Created by vesel on 22.08.2024.
//

#ifndef CRACKPIPE_UTIL_H
#define CRACKPIPE_UTIL_H

#include <Windows.h>
#include <cstdint>
#include <string>

bool bypass_vmp();

uintptr_t scan_manual(uint8_t *start, unsigned long size_of_image, const char *pattern);

void replace_all(
        std::string &s,
        std::string const &toReplace,
        std::string const &replaceWith
);

uintptr_t scan(const char *module, const char *pattern);

void remove_hooks();

void unhook_and_leave_thread();

void unhook_and_leave();

#endif //CRACKPIPE_UTIL_H
