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
    starttls.c
    trust.c
    validate.c
)

add_executable(tlspool ${tlspool_SRC})
target_link_libraries(tlspool
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
)

install(
    TARGETS tlspool
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
