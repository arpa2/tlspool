include_directories(${BDB_INCLUDE_DIR})

add_library(_tool_common OBJECT runterminal.c ../src/donai.c)
target_compile_definitions(_tool_common PUBLIC -DDONAI_ONLY_TEXTPROC)

add_executable(tlspool-test-client testcli.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(tlspool-test-client tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-test-server testsrv.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(tlspool-test-server tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-test-peer testpeer.c socket.c chat_builtin.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(tlspool-test-peer tlspool_shared ${pthread_LIBRARIES})

add_executable(tlstunnel tlstunnel.c chat_builtin.c)
target_link_libraries(tlstunnel tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-ping pingpool.c)
target_link_libraries(tlspool-ping tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-ping-async pingpool-async.c)
target_link_libraries(tlspool-ping-async tlspool_async_shared ${pthread_LIBRARIES})

add_executable(tlspool-localid-select lidsel.c)
target_link_libraries(tlspool-localid-select tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-pin-entry pinentry.c)
target_link_libraries(tlspool-pin-entry tlspool_shared ${pthread_LIBRARIES})

add_executable(tlspool-localid-get get_localid.c)
target_link_libraries(tlspool-localid-get tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-localid-set set_localid.c)
target_link_libraries(tlspool-localid-set tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-disclose-get get_disclose.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(tlspool-disclose-get tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-disclose-set set_disclose.c)
target_link_libraries(tlspool-disclose-set tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-trust-get get_trust.c $<TARGET_OBJECTS:_tool_common>)
target_link_libraries(tlspool-trust-get tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-trust-set set_trust.c)
target_link_libraries(tlspool-trust-set tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(tlspool-db-have have_db.c)
target_link_libraries(tlspool-db-have tlspool_shared ${BDB_LIBRARY} ${pthread_LIBRARIES})

add_executable(pgp11-genkey pgp11_genkey.c)
target_include_directories(pgp11-genkey PUBLIC ${P11-Kit_INCLUDE_DIR} ${OpenLDAP_INCLUDE_DIRS})
target_link_libraries(pgp11-genkey ${P11-Kit_LIBRARY} crypto)

add_executable(tlspool-configvar configvar.c)
target_link_libraries(tlspool-configvar tlspool_shared ${pthread_LIBRARIES})

install(
    TARGETS
        tlspool-configvar
        tlspool-disclose-get
        tlspool-localid-get
        tlspool-trust-get
        tlspool-db-have
        tlspool-localid-select
        tlspool-pin-entry
        tlspool-ping
        tlspool-ping-async
        tlspool-disclose-set
        tlspool-localid-set
        tlspool-trust-set
        tlspool-test-client
        tlspool-test-server
        # tlspool-test-peer # doesn't work yet?
        pgp11-genkey
        tlstunnel
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
