add_definitions(-fPIC)  # Compile flag

add_executable(testcli testcli.c)
target_link_libraries(testcli tlspool_shared ${pthread_LIBRARIES})
