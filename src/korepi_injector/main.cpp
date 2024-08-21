#include <Windows.h>
#include <TlHelp32.h>
#include <format>
#include <filesystem>
#include "../Logger.h"
#include "../util.h"
#include "manual_map.h"
#include "SimpleIni.h"

static CSimpleIniA ini;

std::optional<std::string> SelectFile(const char *filter, const char *title) {
    auto currPath = std::filesystem::current_path();

    // common dialog box structure, setting all fields to 0 is important
    OPENFILENAMEA ofn = {0};
    char szFile[260] = {0};

    // Initialize remaining fields of OPENFILENAME structure
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = reinterpret_cast<LPSTR>(&szFile);
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.lpstrTitle = title;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    std::optional<std::string> result = {};
    if (GetOpenFileNameA(&ofn) == TRUE)
        result = std::string(szFile);

    std::filesystem::current_path(currPath);
    return result;
}


std::optional<std::string>
GetOrSelectPath(CSimpleIniA &ini, const char *section, const char *name, const char *friendName, const char *filter) {
    auto savedPath = ini.GetValue(section, name);
    if (savedPath != nullptr)
        return std::string(reinterpret_cast<const char *const>(savedPath));

    DBG("%s path not found. Please point to it manually.\n", friendName);

    auto titleStr = std::format("Select {}", friendName);
    auto selectedPath = SelectFile(filter, titleStr.c_str());
    if (!selectedPath)
        return {};

    ini.SetValue(section, name, selectedPath->c_str());
    return selectedPath;
}

int FindProcessId(const std::string &processName) {
    int pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            std::wstring ws(process.szExeFile);
            if (std::string(ws.begin(), ws.end()) == processName) {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    return pid;
}

bool OpenGenshinProcess(HANDLE *phProcess, HANDLE *phThread) {


    auto filePath = GetOrSelectPath(ini, "Inject", "GenshinPath", "genshin path",
                                    "Executable\0GenshinImpact.exe;YuanShen.exe\0");
    auto commandline = ini.GetValue("Inject", "GenshinCommandLine");

    LPSTR lpstr = commandline == nullptr ? nullptr : const_cast<LPSTR>(commandline);
    if (!filePath)
        return false;

    DWORD pid = FindProcessId("explorer.exe");
    if (pid == 0) {
        ERR("Can't find 'explorer' pid!\n");
        return false;
    }

    std::string CurrentDirectory = filePath.value();
    int pos = CurrentDirectory.rfind("\\", CurrentDirectory.length());
    CurrentDirectory = CurrentDirectory.substr(0, pos);
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    HANDLE hToken;
    BOOL TokenRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    if (!TokenRet) {
        ERR("Privilege escalation failed!\n");
        return false;
    }
    SIZE_T lpsize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &lpsize);

    char *temp = new char[lpsize];
    LPPROC_THREAD_ATTRIBUTE_LIST AttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST) temp;
    InitializeProcThreadAttributeList(AttributeList, 1, 0, &lpsize);
    if (!UpdateProcThreadAttribute(AttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &handle, sizeof(HANDLE), NULL, NULL)) {
        DBG("UpdateProcThreadAttribute failed ! (%d).\n\n", GetLastError());
    }
    if (!handle) {
        ERR("Couldn't get explorer handle");
    }
    STARTUPINFOEXA si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = AttributeList;

    PROCESS_INFORMATION pi{};
    BOOL result = CreateProcessAsUserA(hToken, filePath->c_str(), lpstr,
                                       0, 0, 0, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, 0,
                                       CurrentDirectory.c_str(), (LPSTARTUPINFOA) &si, &pi);

    bool isOpened = result;
    if (isOpened) {
        ini.SaveFile("cfg.ini");
        *phThread = pi.hThread;
        *phProcess = pi.hProcess;
    } else {
        ERR("Failed to create game process. %d\n", GetLastError());
        ERR("If you have problem with GenshinImpact.exe path. You can change it manually in cfg.ini.\n");
    }

    DeleteProcThreadAttributeList(AttributeList);
    delete[] temp;
    return isOpened;
}


int main(int argc, char *argv[]) {
    ini.SetUnicode();
    ini.LoadFile("cfg.ini");
    INIT_LOGGER("CrackPipe", RGB(74, 255, 155), RGB(35, 173, 252), RGB(252, 35, 60), RGB(71, 245, 103));
    HANDLE hProcess, hThread;
    if (!OpenGenshinProcess(&hProcess, &hThread)) {
        ERR("Failed to open GenshinImpact process.\n\n");
        system("pause");
        return 1;
    }
    const char *val = ini.GetValue("inject", "secrets");
    if (!val) {
        val = R"({{"path":"{}","discordId":"0","role":"31","secret_extra":"frAQBc8W","isEnterDoorLoad":"true"}})";
        ini.SetValue("inject", "secrets", val);
    }
    ini.SaveFile("cfg.ini");

    std::string filename = (argc == 2 ? argv[1] : "korepi.dll");
    std::filesystem::path currentDllPath = std::filesystem::current_path() / filename;
    std::string path = std::filesystem::current_path().string();
    std::string i_want_to_be_cool_when_i_grow_up = std::vformat(
            val,
            std::make_format_args(path));
    replace_all(i_want_to_be_cool_when_i_grow_up, "\\", "\\\\");
    void *korepibase = ManualMapDLL_(hProcess, currentDllPath.string(), i_want_to_be_cool_when_i_grow_up);
    std::string basestr = std::format("{};test", korepibase);
    LOG("%s\n", basestr.c_str());
    if (std::filesystem::exists(std::filesystem::current_path() / "crackpipedev.dll")) {
        ManualMapDLL_(hProcess, (std::filesystem::current_path() / "crackpipedev.dll").string(), basestr);
    } else {
        ManualMapDLL_(hProcess, (std::filesystem::current_path() / "crackpipe.dll").string(), basestr);
    }
    ResumeThread(hThread);
    system("pause");
}