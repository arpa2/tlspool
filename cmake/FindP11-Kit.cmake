# - Try to find P11-Kit
#
# Once done this will define the following CMake variables:
#
#  - P11-Kit_FOUND
#  - P11-Kit_INCLUDE_DIRS
#  - P11-Kit_LIBRARIES
#  - P11-Kit_DEFINITIONS
#
include(FeatureSummary)

set_package_properties(P11-Kit PROPERTIES
    DESCRIPTION "PKCS#11 module loader"
    URL "https://p11-glue.freedesktop.org/p11-kit.html"
)

find_package(PkgConfig)
pkg_check_modules(PC_p11kit QUIET p11-kit-1)

set(P11-Kit_DEFINITIONS ${PC_p11kit_CFLAGS_OTHER})

find_path(P11-Kit_INCLUDE_DIR
    p11-kit/pkcs11.h
    HINTS ${PC_p11kit_INCLUDEDIR} ${PC_p11kit_INCLUDE_DIRS}
)

find_library(P11-Kit_LIBRARY
    NAMES p11-kit
    HINTS ${PC_p11kit_LIBDIR} ${PC_p11kit_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    P11-Kit
    DEFAULT_MSG
    P11-Kit_LIBRARY P11-Kit_INCLUDE_DIR
)
mark_as_advanced(P11-Kit_INCLUDE_DIR P11-Kit_LIBRARY)

if(P11-Kit_FOUND)
    set(P11-Kit_INCLUDE_DIRS ${P11-Kit_INCLUDE_DIR})
    set(P11-Kit_LIBRARIES ${P11-Kit_LIBRARY})
endif()

