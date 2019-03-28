# The modern CMake standard is *_INCLUDE_DIRS, but not all modules
# follow that standard.
#
# At least on FreeBSD, put BDB_INCLUDE_DIR first, since the
# TLSPool code does #include <db.h>, and there are several
# of those; find the BDB version, db5/db.h, first.
include_directories(
    ${BDB_INCLUDE_DIR}
    ${GNUTLS_INCLUDE_DIR}
    ${Libldns_INCLUDE_DIRS}
    ${LibTASN1_INCLUDE_DIRS}
    ${OpenLDAP_INCLUDE_DIRS}
    ${P11-Kit_INCLUDE_DIRS}
    ${Quick-DER_INCLUDE_DIRS}
    ${Unbound_INCLUDE_DIR}
)

add_com_err_table (errortable)

set(tlspool_SRC
    cache.c
    config.c
    ctlkey.c
    daemon.c
    donai.c
    error.c
    lidentry.c
    manage.c
    online.c
    pgp.c
    pinentry.c
    remote.c
    service.c
    ${STARTTLS_DRIVER}.c
    trust.c
    validate.c
    ${COM_ERR_errortable_SRC}
)

add_executable(tlspool-daemon ${tlspool_SRC})
target_compile_definitions(tlspool-daemon PRIVATE -DTLSPOOL_VERSION="${TLSPool_VERSION}")
target_link_libraries(tlspool-daemon
    ${BDB_LIBRARY}
    ${GNUTLS_LIBRARY}
    ${GnuTLSDane_LIBRARIES}
    ${Libldns_LIBRARIES}
    ${LibTASN1_LIBRARIES}
    ${OpenLDAP_LIBRARIES}
    ${P11-Kit_LIBRARIES}
    ${Quick-DER_LIBRARIES}
    ${Unbound_LIBRARIES}
    ${pthread_LIBRARIES}
    ${com_err_LIBRARIES}
)

install(
    TARGETS tlspool-daemon
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/include/tlspool/
    DESTINATION /usr/include/tlspool
)

