//
// Created by vesel on 04.08.2024.
//

#ifndef LOL_LOGGER_H
#define LOL_LOGGER_H

#include "macros.h"
#include <vector>
#include <memory>

typedef struct {
    const char *type;
    const char *line_number;
    unsigned short color;
    char *msg;
} logMessage;

class Logger {
public:
    ~Logger();

    void Init(const char *name, COLORREF name_color, COLORREF info_color, COLORREF error_color, COLORREF success_color);

    void SetupConsole(bool free);

    void ColorPrint(const char *text, unsigned short color);

    bool Info(const char *ln, const char *fmt, ...);

    bool Debug(const char *ln, const char *fmt, ...);

    bool Error(const char *ln, const char *fmt, ...);

    bool Success(const char *ln, const char *fmt, ...);

    bool IsInitialized() {
        return this->name != nullptr;
    };

private:
    bool
    Printf(const char *type, const char *line_number, unsigned short color, const char *fmt, va_list va, bool replay);

    void ReplayLog();

    const char *name;
    HANDLE out;
    COLORREF color_table[16];
    COLORREF original_color_table[16];
    std::vector<logMessage> message_log;

};

inline Logger g_logger;

#define INIT_LOGGER(name, name_color, info_color, error_color, success_color) \
    g_logger.Init(name, name_color, info_color, error_color, success_color); \
    g_logger.SetupConsole(false);                                                 \
    g_logger.ColorPrint("Welcome to ", 0x3); \
    g_logger.ColorPrint(name, 0xd); \
    g_logger.ColorPrint("!!!\n", 0x4)

#define LOG(fmt, ...) g_logger.Info(STR(__LINE__), fmt, __VA_ARGS__)
#define ERR(fmt, ...) g_logger.Error(STR(__LINE__), fmt, __VA_ARGS__)
#define DBG(fmt, ...) g_logger.Debug(STR(__LINE__), fmt, __VA_ARGS__)
#define SUC(fmt, ...) g_logger.Success(STR(__LINE__), fmt, __VA_ARGS__)

#endif //LOL_LOGGER_H
