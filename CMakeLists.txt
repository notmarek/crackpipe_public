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

target_link_libraries(crackpipe minhook)
target_include_directories(crackpipe PRIVATE minhook/src)

add_subdirectory(minhook)
