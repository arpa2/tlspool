project(tlspool-pulleyback C)
if(NOT "${CMAKE_HOST_SYSTEM}" MATCHES ".*Windows.*")

# TODO:
#  - CFLAGS from Makefile are -ggdb3 -O0 -fPIC -std=gnu11
#  - CFLAGS on Windows    are -D_WIN32_WINNT=0x0600 -I ../include/windows
#  - On Windows, extra source and extra libraries to link to

add_definitions(-fPIC)  # Compile flag

# TODO: this should get some kind of support in SteamWorks so we can get
#       consistent install paths, and the PREFIX property is set right.

include_directories(${BDB_INCLUDE_DIR} ${Quick-DER_INCLUDE_DIRS})
add_library(pulleyback_tlspool SHARED
    api.c connect.c parse.c update.c
    )
set_target_properties(pulleyback_tlspool PROPERTIES PREFIX "")  # no "lib"
target_link_libraries(pulleyback_tlspool ${BDB_LIBRARY} ${Quick-DER_LIBRARIES})

install(
    TARGETS pulleyback_tlspool
    LIBRARY DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/steamworks/pulleyback/
    ARCHIVE DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/steamworks/pulleyback/
)
endif()
