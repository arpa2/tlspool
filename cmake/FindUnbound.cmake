# Copied from the Fenrir project, and drastically modified to
# match modern CMake style.

FIND_PATH(Unbound_INCLUDE_DIR
  NAMES unbound.h
  PATH_SUFFIXES include/ include/unbound/
  PATHS "${PROJECT_SOURCE_DIR}"
  ${UNBOUND_ROOT}
  $ENV{UNBOUND_ROOT}
  /usr/local/
  /usr/
)

IF(Unbound_INCLUDE_DIR)
  SET(Unbound_FOUND TRUE)
ELSE()
  SET(Unbound_FOUND FALSE)
ENDIF()

IF(Unbound_FOUND)
  MESSAGE(STATUS "Found unbound in ${Unbound_INCLUDE_DIR}")
ELSE()
  IF(Unbound_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find \"unbound\" library")
  ENDIF()
ENDIF()


find_library(Unbound_LIBRARY
    NAMES unbound
    HINTS /usr/local /usr
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    Unbound
    DEFAULT_MSG
    Unbound_LIBRARY Unbound_INCLUDE_DIR
)
mark_as_advanced(Unbound_INCLUDE_DIR Unbound_LIBRARY)

if(Unbound_FOUND)
    set(Unbound_INCLUDE_DIRS ${Unbound_INCLUDE_DIR})
    set(Unbound_LIBRARIES ${Unbound_LIBRARY})
endif()

