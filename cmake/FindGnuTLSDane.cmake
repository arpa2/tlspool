# - Try to find GnuTLS DANE extensions
#
# Once done this will define the following CMake variables:
#
#  - GnuTLSDane_FOUND
#  - GnuTLSDane_INCLUDE_DIRS
#  - GnuTLSDane_LIBRARIES
#  - GnuTLSDane_DEFINITIONS
#
include(FeatureSummary)

set_package_properties(GnuTLSDane PROPERTIES
    DESCRIPTION "GnuTLS DANE extensions"
    URL "https://www.gnutls.org/"
)

find_package(GnuTLS REQUIRED)
find_package(PkgConfig)
pkg_check_modules(PC_gtlsdane QUIET gnutls-dane)

set(GnuTLSDane_DEFINITIONS ${PC_gtlsdane_CFLAGS_OTHER})

find_path(GnuTLSDane_INCLUDE_DIR
    gnutls/dane.h
    HINTS ${PC_gtlsdane_INCLUDEDIR} ${PC_gtlsdane_INCLUDE_DIRS}
)

find_library(GnuTLSDane_LIBRARY
    NAMES gnutls-dane
    HINTS ${PC_gtlsdane_LIBDIR} ${PC_gtlsdane_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    GnuTLSDane
    DEFAULT_MSG
    GnuTLSDane_LIBRARY GnuTLSDane_INCLUDE_DIR
)
mark_as_advanced(GnuTLSDane_INCLUDE_DIR GnuTLSDane_LIBRARY)

if(GnuTLSDane_FOUND)
    set(GnuTLSDane_INCLUDE_DIRS ${GnuTLSDane_INCLUDE_DIR})
    set(GnuTLSDane_LIBRARIES ${GnuTLSDane_LIBRARY})
endif()

