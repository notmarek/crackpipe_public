//
// Created by vesel on 13.08.2024.
//

#ifndef LOL_MANUAL_MAP_H
#define LOL_MANUAL_MAP_H

#pragma once

#include <string>

void *ManualMapDLL_(HANDLE hProc, const std::string &filepath, const std::string &security);

void *ManualMapDLL(HANDLE hProc, BYTE *pSrcData, SIZE_T FileSize, const std::string &security, bool ClearHeader = false,
                   bool ClearNonNeededSections = false, bool AdjustProtections = true, bool SEHExceptionSupport = true,
                   DWORD fdwReason = DLL_PROCESS_ATTACH);

#endif //LOL_MANUAL_MAP_H
