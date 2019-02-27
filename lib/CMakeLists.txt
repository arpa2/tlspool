if("${CMAKE_HOST_SYSTEM}" MATCHES ".*Windows.*")
# TODO 	libtlspool_lidentry.c and libtlspool_pinentry.c for Windows
	set(libtlspool_SRC
		libtlspool.c
		libtlspool_configvar.c
		windows/syslog.c
		windows/socketpair.c
	)
else()
	set(libtlspool_SRC
		libtlspool.c
		libtlspool_lidentry.c	
		libtlspool_pinentry.c	
		libtlspool_configvar.c
	)
endif()


# Compile the files only once
add_library(_libtlspool OBJECT ${libtlspool_SRC})

# Make libraries out of the resulting objects; these
# need to have unique names for CMake, and use OUTPUT_NAME
# so that they are called libtlspool.{so,a}.
add_library(tlspool_shared SHARED $<TARGET_OBJECTS:_libtlspool>)
set_target_properties(tlspool_shared PROPERTIES
    OUTPUT_NAME tlspool
)
add_library(tlspool_static STATIC $<TARGET_OBJECTS:_libtlspool>)
set_target_properties(tlspool_static PROPERTIES
    OUTPUT_NAME tlspool
)

install(
    TARGETS tlspool_shared
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(
    TARGETS tlspool_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

option(LANGUAGE_SUPPORT_PYTHON
	"Add language support for Python"
	OFF)

if(LANGUAGE_SUPPORT_PYTHON)
    add_subdirectory(python)
endif()
