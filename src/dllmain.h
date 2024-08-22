//
// Created by vesel on 21.08.2024.
//

#ifndef CRACKPIPE_DLLMAIN_H
#define CRACKPIPE_DLLMAIN_H

#include <Windows.h>
#include "exe.h"

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, const char *data);
#endif //CRACKPIPE_DLLMAIN_H
