project(tlspool-pulleyback C)

# TODO:
#  - CFLAGS from Makefile are -ggdb3 -O0 -fPIC -std=gnu11
#  - CFLAGS on Windows    are -D_WIN32_WINNT=0x0600 -I ../include/windows
#  - On Windows, extra source and extra libraries to link to

add_definitions(-fPIC)  # Compile flag

include_directories(${BDB_INCLUDE_DIR} ${Quick-DER_INCLUDE_DIRS})
add_library(pulleyback_tlspool SHARED
    api.c connect.c parse.c update.c
    )
target_link_libraries(pulleyback_tlspool ${BDB_LIBRARY} ${Quick-DER_LIBRARIES})
