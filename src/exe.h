//
// Created by vesel on 22.08.2024.
//

#ifndef CRACKPIPE_EXE_H
#define CRACKPIPE_EXE_H
struct StartupData {
    void *pBase;
    char *korepibase;
    char *path;
};

void start(StartupData *startupData);

#endif //CRACKPIPE_EXE_H
