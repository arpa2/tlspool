# - Try to find LibTASN1 (dependency for GnuTLS)
#
# Once done this will define the following CMake variables:
#
#  - LibTASN1_FOUND
#  - LibTASN1_INCLUDE_DIRS
#  - LibTASN1_LIBRARIES
#  - LibTASN1_DEFINITIONS
#
include(FeatureSummary)

set_package_properties(LibTASN1 PROPERTIES
    DESCRIPTION "ASN.1 library used by GnuTLS"
    URL "http://www.gnu.org/software/libtasn1/"
)

find_package(PkgConfig)
pkg_check_modules(PC_libtasn1 QUIET libtasn1)

set(LibTASN1_DEFINITIONS ${PC_libtasn1_CFLAGS_OTHER})

find_path(LibTASN1_INCLUDE_DIR
    libtasn1.h
    HINTS ${PC_libtasn1_INCLUDEDIR} ${PC_libtasn1_INCLUDE_DIRS}
)

find_library(LibTASN1_LIBRARY
    NAMES tasn1
    HINTS ${PC_libtasn1_LIBDIR} ${PC_libtasn1_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibTASN1
    DEFAULT_MSG
    LibTASN1_LIBRARY LibTASN1_INCLUDE_DIR
)
mark_as_advanced(LibTASN1_INCLUDE_DIR LibTASN1_LIBRARY)

if(LibTASN1_FOUND)
    set(LibTASN1_INCLUDE_DIRS ${LibTASN1_INCLUDE_DIR})
    set(LibTASN1_LIBRARIES ${LibTASN1_LIBRARY})
endif()

