cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

project(tlspool C)

include (FeatureSummary)
find_package (ARPA2CM 0.5 QUIET NO_MODULE)
set_package_properties (ARPA2CM PROPERTIES
    DESCRIPTION "CMake modules for ARPA2 projects"
    TYPE REQUIRED
    URL "https://github.com/arpa2/arpa2cm/"
    PURPOSE "Required for the CMake build system for ${PROJECT}"
)
if (ARPA2CM_FOUND)
    set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${ARPA2CM_MODULE_PATH})
else()
    feature_summary (WHAT ALL)
    message (FATAL_ERROR "ARPA2CM is required.")
endif()

include(MacroEnsureOutOfSourceBuild)
include(MacroGitVersionInfo)

include(CTest)
include(FeatureSummary)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

macro_ensure_out_of_source_build(
    "Do not build TLSPool in the source directory.")
get_version_from_git(TLSPool 0.20)

# Finding dependencies, find-modules provided by:
# - "ARPA" is shipped with ARPA2CM
# - "Module" is shipped with CMake itself
# - "Config" is shipped with that software package
#
find_package(BDB REQUIRED)         # ARPA
find_package(GnuTLS REQUIRED)      # Module
find_package(GnuTLSDane REQUIRED)  # ARPA
find_package(KERBEROS REQUIRED)    # Local
find_package(Libldns REQUIRED)     # ARPA
find_package(LibTASN1 REQUIRED)    # ARPA
find_package(OpenLDAP REQUIRED)    # ARPA
find_package(P11-Kit REQUIRED)     # ARPA
find_package(Quick-DER 1.2.4 REQUIRED NO_MODULE)  # Config
find_package(Unbound REQUIRED)     # ARPA

# TODO: look for TLS-KDH

if(GnuTLSDane_FOUND)
    add_definitions(-DHAVE_GNUTLS_DANE)
endif()


feature_summary(WHAT ALL VAR _features)
message(STATUS ${_features})

option(TEST_UNDER_TLSPOOL "Test under the assumption of an available TLS Pool" OFF)

option(EXPERIMENTAL_SRP_SUPPORT "Enable support for SRP based on relative file names" OFF)
if (EXPERIMENTAL_SRP_SUPPORT)
    add_definitions(-DEXPERIMENTAL_SRP)
endif()

# These are compile flags, not definitions, but it happens to work.
add_definitions(-fPIC -pthread)
# Pretend we looked for pthread libraries, so that we can write
# cmake code that looks consistent.
set(pthread_LIBRARIES pthread)
# Always include the TLSPool top-level include/ dir.
include_directories(${CMAKE_SOURCE_DIR}/include)

enable_testing()

add_subdirectory(src)
add_subdirectory(lib)
add_subdirectory(tool)
add_subdirectory(pulleyback)
add_subdirectory(doc)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
