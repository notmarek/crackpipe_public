cmake_minimum_required(VERSION 3.5)
project(CrackPipe)
set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

set(SRC src/exe.cpp
        src/exe.h
        src/injector.cpp
        src/keyauth_helpers.h
        src/Logger.cpp
        src/Logger.h
        src/veh_hooks.cpp
        src/veh_hooks.h
        src/macros.h
        src/injector.h
        src/util.cpp
        src/util.h
        src/dllmain.cpp
        src/dllmain.h
        src/korepi_injector/korepi_injector.cpp
        src/korepi_injector/korepi_injector.h
        src/korepi_injector/manual_map.cpp
        src/korepi_injector/manual_map.h)
add_executable(hellpipe ${SRC})
add_executable(hellpipedev ${SRC})
SET_TARGET_PROPERTIES(hellpipe PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")
SET_TARGET_PROPERTIES(hellpipedev PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")
target_compile_definitions(hellpipedev PRIVATE CRACKPIPEDEV)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(zydis)
add_subdirectory(minhook)
add_subdirectory(simpleini)



target_link_libraries(hellpipe minhook SimpleIni)
target_link_libraries(hellpipedev minhook Zydis SimpleIni)

target_include_directories(hellpipe PRIVATE minhook/src SimpleIni)
target_include_directories(hellpipedev PRIVATE minhook/src zydis/include SimpleIni)
