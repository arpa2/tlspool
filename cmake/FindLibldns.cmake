# - Try to find Libldns (NLNet DNS resolving library)
#
# Once done this will define the following CMake variables:
#
#  - Libldns_FOUND
#  - Libldns_INCLUDE_DIRS
#  - Libldns_LIBRARIES
#  - Libldns_DEFINITIONS
#
include(FeatureSummary)

set_package_properties(Libldns PROPERTIES
    DESCRIPTION "simplify DNS programming"
    URL "https://github.com/threatstack/libldns"
)

find_package(PkgConfig)
pkg_check_modules(PC_libldns QUIET libldns)

set(Libldns_DEFINITIONS ${PC_libldns_CFLAGS_OTHER})

find_path(Libldns_INCLUDE_DIR
    ldns/ldns.h
    HINTS ${PC_libldns_INCLUDEDIR} ${PC_libldns_INCLUDE_DIRS}
)

find_library(Libldns_LIBRARY
    NAMES ldns
    HINTS ${PC_libldns_LIBDIR} ${PC_libldns_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    Libldns
    DEFAULT_MSG
    Libldns_LIBRARY Libldns_INCLUDE_DIR
)
mark_as_advanced(Libldns_INCLUDE_DIR Libldns_LIBRARY)

if(Libldns_FOUND)
    set(Libldns_INCLUDE_DIRS ${Libldns_INCLUDE_DIR})
    set(Libldns_LIBRARIES ${Libldns_LIBRARY})
endif()

