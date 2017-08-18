# Relative to here
set(doc_SRCS
    socketprotocol.rst
    databases.rst
    identities.rst
    pkcs11.rst
    validation.md
    startxxx.md
    p2p-tls.md
    tool/ircproxy-explained.md
    localid-selection.md
    anonymising-precursor.md
)

# Relative to top-level
set(license_SRCS
    ${CMAKE_SOURCE_DIR}/COPYRIGHT.MD
    ${CMAKE_SOURCE_DIR}/LICENSE-DAEMON.MD
    ${CMAKE_SOURCE_DIR}/LICENSE-DOCS.MD
    ${CMAKE_SOURCE_DIR}/LICENSE-USERSPACE.MD
    # README
    # INSTALL
    # TODO
)

# Relative to here
set(man3_SRCS
    tlspool_socket
    tlspool_starttls
    tlspool_ping
    tlspool_prng
    tlspool_pin_service
    tlspool_localid_service
    tlspool_control_detach
    tlspool_control_reattach
    tlspool_configvar
)
set(man8_SRCS tlspool tlstunnel)

install(FILES ${doc_SRCS} ${license_SRCS} DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/tlspool/)

foreach(m ${man3_SRCS})
    install(FILES man/${m}.man DESTINATION ${CMAKE_INSTALL_MANDIR}/man3/ RENAME ${m}.3)
endforeach()
foreach(m ${man8_SRCS})
    install(FILES man/${m}.man DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/ RENAME ${m}.8)
endforeach()

