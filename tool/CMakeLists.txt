include_directories(${BDB_INCLUDE_DIR})

add_library(_tool_common OBJECT runterminal.c ../src/donai.c)
target_compile_definitions(_tool_common PUBLIC -DDONAI_ONLY_TEXTPROC)

add_executable(testcli testcli.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(testcli tlspool_shared ${pthread_LIBRARIES})

add_executable(testsrv testsrv.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(testsrv tlspool_shared ${pthread_LIBRARIES})

add_executable(testpeer testpeer.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(testpeer tlspool_shared ${pthread_LIBRARIES})

add_executable(tlstunnel tlstunnel.c chat_builtin.c)
target_link_libraries(tlstunnel tlspool_shared ${pthread_LIBRARIES})

add_executable(pingpool pingpool.c)
target_link_libraries(pingpool tlspool_shared ${pthread_LIBRARIES})

add_executable(lidsel lidsel.c)
target_link_libraries(lidsel tlspool_shared ${pthread_LIBRARIES})

add_executable(pinentry pinentry.c)
target_link_libraries(pinentry tlspool_shared ${pthread_LIBRARIES})

add_executable(get_localid get_localid.c)
target_link_libraries(get_localid tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(set_localid set_localid.c)
target_link_libraries(set_localid tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(get_disclose get_disclose.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(get_disclose tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(set_disclose set_disclose.c)
target_link_libraries(set_disclose tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(get_trust get_trust.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(get_trust tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(set_trust set_trust.c)
target_link_libraries(set_trust tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(have_db have_db.c)
target_link_libraries(have_db tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(pgp11_genkey pgp11_genkey.c)
target_include_directories(pgp11_genkey PUBLIC ${P11-Kit_INCLUDE_DIR} ${OpenLDAP_INCLUDE_DIRS})
target_link_libraries(pgp11_genkey ${P11-Kit_LIBRARY} crypto)

add_executable(configvar configvar.c)
target_link_libraries(configvar tlspool_shared ${pthread_LIBRARIES})

install(
    TARGETS
        configvar
        get_disclose
        get_localid
        get_trust
        have_db
        lidsel
        pgp11_genkey
        pinentry
        pingpool
        set_disclose
        set_localid
        set_trust
        testcli
        testsrv
        # testpeer # doesn't work yet?
        tlstunnel
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
