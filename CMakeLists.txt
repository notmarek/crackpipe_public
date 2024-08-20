cmake_minimum_required(VERSION 3.5)
project(CrackPipe)
set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

add_library(crackpipe SHARED src/exe.cpp
        src/injector.cpp
        src/keyauth_helpers.h
        src/Logger.cpp
        src/Logger.h
        src/veh_hooks.cpp
        src/veh_hooks.h
        src/macros.h
        src/injector.h
        src/util.h)

add_library(crackpipedev SHARED src/exe.cpp
        src/injector.cpp
        src/keyauth_helpers.h
        src/Logger.cpp
        src/Logger.h
        src/veh_hooks.cpp
        src/veh_hooks.h
        src/macros.h
        src/injector.h
        src/util.h)
target_compile_definitions(crackpipedev PRIVATE CRACKPIPEDEV)
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(zydis)
add_subdirectory(minhook)
add_subdirectory(simpleini)


target_link_libraries(crackpipe minhook )
target_link_libraries(crackpipedev minhook Zydis)
target_include_directories(crackpipe PRIVATE minhook/src )
target_include_directories(crackpipedev PRIVATE minhook/src zydis/include)


add_executable(korepi_injector src/korepi_injector/manual_map.cpp src/korepi_injector/manual_map.h src/Logger.cpp src/Logger.h
        src/korepi_injector/main.cpp src/util.h)
target_link_libraries(korepi_injector SimpleIni minhook)
target_include_directories(korepi_injector PRIVATE simpleini minhook/src)
SET_TARGET_PROPERTIES(korepi_injector PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")


