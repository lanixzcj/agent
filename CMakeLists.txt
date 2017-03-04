cmake_minimum_required(VERSION 2.8.4)
project(client)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES client.cpp client.h lib/net.h lib/net.c
        lib/debug_msg.h lib/debug_msg.c lib/file.h lib/file.c metrics.h metrics.cpp mon_value.h
        lib/cJSON.h lib/cJSON.c conf.h conf.cpp lib/http-client-c.h
        lib/stringx.h lib/urlparser.h lib/utlist.h lib/uthash.h lib/thpool.c lib/thpool.h
        )
add_executable(client ${SOURCE_FILES})
include_directories(${PROJECT_SOURCE_DIR}/lib)
target_link_libraries(client -lm -lpthread -lcrafter -lpcap -lresolv -g)