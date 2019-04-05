set(libtlspool_SRC
    libtlspool.c
    libtlspool_lidentry.c
    libtlspool_pinentry.c
    libtlspool_configvar.c
)

set(libtlspool_async_SRC
    libtlspool_async.c
    libtlspool_configvar.c
)

set(libpavlov_SRC
    libpavlov.c
)

# Include the error table from ../src
use_com_err_table (errortable)

# Compile the files only once
add_library(_libtlspool OBJECT ${libtlspool_SRC})
add_library(_libtlspool_async OBJECT ${libtlspool_async_SRC})
add_library(_libpavlov OBJECT ${libpavlov_SRC})

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

# The asynchronous library is much more basic;
# all functions are needed and there is no
# "frivolous" support for PIN entry or callbacks.
add_library(tlspool_async_shared SHARED $<TARGET_OBJECTS:_libtlspool_async>)
set_target_properties(tlspool_async_shared PROPERTIES
     OUTPUT_NAME tlspool_async
)
add_library(tlspool_async_static STATIC $<TARGET_OBJECTS:_libtlspool_async>)
set_target_properties(tlspool_async_static PROPERTIES
    OUTPUT_NAME tlspool_async
)

# The pavlov library
add_library(pavlov_shared SHARED $<TARGET_OBJECTS:_libpavlov>)
set_target_properties(pavlov_shared PROPERTIES
    OUTPUT_NAME pavlov
)
add_library(pavlov_static STATIC $<TARGET_OBJECTS:_libpavlov>)
set_target_properties(pavlov_static PROPERTIES
    OUTPUT_NAME pavlov
)

# POSIX extended regex on Windows sits in a separate library, gnurx
if ("${CMAKE_HOST_SYSTEM}" MATCHES ".*Windows.*")
    target_link_libraries (pavlov_shared -lgnurx)
    target_link_libraries (pavlov_static -lgnurx)
endif()

install(
    TARGETS tlspool_shared pavlov_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(
    TARGETS tlspool_static pavlov_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    TARGETS tlspool_async_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(
    TARGETS tlspool_async_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

option(LANGUAGE_SUPPORT_PYTHON
	"Add language support for Python"
	OFF)

if(LANGUAGE_SUPPORT_PYTHON)
    add_subdirectory(python)
endif()
