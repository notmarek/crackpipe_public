//
// Created by vesel on 04.08.2024.
//

#include <Windows.h>
#include <cstdio>
#include "Logger.h"
#include "macros.h"

void
Logger::Init(const char *name, COLORREF name_color, COLORREF info_color, COLORREF error_color, COLORREF success_color) {
    this->name = name;
    this->color_table[0x3] = info_color;
    this->color_table[0x4] = error_color;
    this->color_table[0xa] = success_color;
    this->color_table[0xd] = name_color;
}

Logger::~Logger() {
//    this->Info("", "~Logger - resetting console colortable goodbye!\n");
//    CONSOLE_SCREEN_BUFFER_INFOEX info;
//    info.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);
//    GetConsoleScreenBufferInfoEx(this->out, &info);
//    for (int i = 0; i < 16; i++) {
//        info.ColorTable[i] = this->original_color_table[i];
//    }
//    SetConsoleScreenBufferInfoEx(this->out, &info);
}

void Logger::SetupConsole(bool free) {
    if (free) {
        HWND myConsole = GetConsoleWindow(); //window handle
        FreeConsole();
        PostMessage(myConsole, WM_CLOSE, 0, 0);

    }
    if (!GetConsoleWindow())
        AllocConsole();
    this->out = GetStdHandle(STD_OUTPUT_HANDLE);
    freopen_s((FILE **) stdout, "CONOUT$", "w", stdout);
    CONSOLE_SCREEN_BUFFER_INFOEX info;
    info.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);
    GetConsoleScreenBufferInfoEx(this->out, &info);
    for (int i = 0; i < 16; i++) {
        this->original_color_table[i] = info.ColorTable[i];
        if (this->color_table[i] != 0)
            info.ColorTable[i] = this->color_table[i];
    }
    SetConsoleScreenBufferInfoEx(this->out, &info);
}

void Logger::ColorPrint(const char *text, unsigned short color) {
    SetConsoleTextAttribute(this->out, color);
    WriteConsoleA(this->out, text, strlen(text), nullptr, nullptr);
    SetConsoleTextAttribute(this->out, 0x000f);
}

void Logger::ReplayLog() {
    for (logMessage lm: this->message_log) {
        va_list va;
        this->Printf(lm.type, lm.line_number, lm.color, lm.msg, nullptr, true);
                va_end(va);
    }
}

bool Logger::Printf(const char *type, const char *line_number, unsigned short color, const char *fmt, va_list va,
                    bool replay) {
    char buf[8192];
    int len = vsprintf_s(buf, 8192, fmt, va);
    if (!replay) {
        logMessage lm;
        lm.type = type;
        lm.line_number = line_number;
        lm.color = color;
        lm.msg = buf;
        lm.msg = (char *) malloc(len + 1);
        strcpy_s(lm.msg, len + 1, buf);
        message_log.push_back(lm);
    }
    if (!this->out)
        return false;

    SetConsoleTextAttribute(this->out, 0x000f);
    if (!WriteConsoleA(this->out, "[", 1, nullptr, nullptr)) {
        Sleep(800);
        if (!WriteConsoleA(this->out, "[", 1, nullptr, nullptr)) {
            SetupConsole(true);
            this->ColorPrint("Welcome", 0x3);
            this->ColorPrint(" back", 0xa);
            this->ColorPrint(" to ", 0x3);
            this->ColorPrint("CrackPipe", 0xd);
            this->ColorPrint("!!!\n", 0x4);
            this->ReplayLog();
            this->Error(STR(__LINE__), "The console was fucked up, a new one has been allocated!\n");
            return false;
        }
    }
    this->ColorPrint(this->name, 0x000d);
    WriteConsoleA(this->out, ":", 1, nullptr, nullptr);
    this->ColorPrint(type, color);
    WriteConsoleA(this->out, "] ", 2, nullptr, nullptr);
    return !!WriteConsoleA(this->out, &buf, static_cast<DWORD>(strlen(buf)), nullptr, nullptr);
}

bool Logger::Info(const char *ln, const char *fmt, ...) {

    va_list va;
            va_start(va, fmt);
    const bool result = this->Printf("Info", ln, 0x0003, fmt, va, false);
            va_end(va);
    return result;
}

bool Logger::Debug(const char *ln, const char *fmt, ...) {

    va_list va;
            va_start(va, fmt);
    const bool result = Printf("Debug", ln, 0x0008, fmt, va, false);
            va_end(va);
    return result;
}

bool Logger::Error(const char *ln, const char *fmt, ...) {

    va_list va;
            va_start(va, fmt);
    const bool result = Printf("Error", ln, 0x0004, fmt, va, false);
            va_end(va);
    return result;
}


bool Logger::Success(const char *ln, const char *fmt, ...) {
    va_list va;
            va_start(va, fmt);
    const bool result = Printf("Success", ln, 0x000a, fmt, va, false);
            va_end(va);
    return result;
}

