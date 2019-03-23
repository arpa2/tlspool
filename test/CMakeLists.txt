add_definitions(-DDEBUG)
include_directories(${BDB_INCLUDE_DIR})

message(STATUS "Building TLSPool tests\n.. run 'make test' to run them.")

# Because these tests #include sources from elsewhere
add_custom_target(src-validate DEPENDS ../src/validate.c)
add_custom_target(src-onlinecheck DEPENDS ../src/online.c)

### Validation tests
#
#
add_executable(valexprun valexprun.c)
add_dependencies(valexprun src-validate)

file(GLOB valexp_inputs
    LIST_DIRECTORIES false
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/data-valexp-in/
    ${CMAKE_CURRENT_SOURCE_DIR}/data-valexp-in/*)

foreach(t ${valexp_inputs})
    add_test(
        NAME valexp-${t}
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valexprun.sh $<TARGET_FILE:valexprun> ${CMAKE_CURRENT_SOURCE_DIR} ${t}
    )
endforeach()


### Online check
#
#
add_executable(onlinecheck onlinecheck.c ../src/config.c ../src/pgp.c)
add_dependencies(onlinecheck src-onlinecheck)
target_compile_definitions(onlinecheck PUBLIC -DCONFIG_PARSE_ONLY)
target_include_directories(onlinecheck PUBLIC
    ${OpenLDAP_INCLUDE_DIRS}
    ${Quick-DER_INCLUDE_DIRS}
    ${Unbound_INCLUDE_DIR}
)
target_link_libraries(onlinecheck
    ${GNUTLS_LIBRARIES}
    ${Libldns_LIBRARIES}
    ${OpenLDAP_LIBRARIES}
    ${Quick-DER_LIBRARIES}
    ${Unbound_LIBRARY}
)
add_test(
    NAME onlinecheck
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/onlinecheck.sh $<TARGET_FILE:onlinecheck>
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

### Pulleyback Simulation
#
#
add_executable(pulleybacksimu pulleybacksimu.c)
target_link_libraries(pulleybacksimu
    pulleyback_tlspool
)
add_test(
    NAME pulleybacksimu
    COMMAND pulleybacksimu
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

### Run testcli and testsrv under Pypeline
#
#
set (testcli  ${CMAKE_BINARY_DIR}/tool/testcli)
set (testsrv  ${CMAKE_BINARY_DIR}/tool/testsrv)
set (pypeline ${CMAKE_SOURCE_DIR}/test/pypeline)

if (TEST_UNDER_TLSPOOL)
add_test(
	NAME ping6dance-srv2cli
	COMMAND ${pypeline}
		${testcli} . IP:LOCAL TCP:PORT      -5 -sSv "" ping EPROTONOTSUPPORTED ping6 pong6
		--
		${testsrv} . IP:LOCAL TCP:PORT SIG:HUP -sSv    ping EPROTONOTSUPPORTED ping6 pong6
)
endif()

if (TEST_UNDER_TLSPOOL)
add_test(
	NAME ping6dance-cli2srv
	COMMAND ${pypeline}
		${testcli} . IP:LOCAL TCP:PORT      -5 -sSv    ping EPROTONOTSUPPORTED ping6 pong6
		--
		${testsrv} . IP:LOCAL TCP:PORT SIG:HUP -sSv "" ping EPROTONOTSUPPORTED ping6 pong6
)
endif()

### Run pingpool-async to test the asynchronous API
#
#

if (TEST_UNDER_TLSPOOL)
add_test(
	NAME pingpool-async
	COMMAND pingpool-async
)
endif()
