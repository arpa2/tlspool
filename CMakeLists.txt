cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

project(tlspool C)

include(MacroEnsureOutOfSourceBuild)
include(MacroGitVersionInfo)

include(CTest)
include(FeatureSummary)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

macro_ensure_out_of_source_build(
    "Do not build TLSPool in the source directory.")
get_version_from_git(TLSPool 0.20.0)

# Finding dependencies; the ones marked "Local" have a CMake
# module included with TLSPool under cmake/, the ones marked
# "Module" use a module shipped with CMake, the ones marked
# "Config" use the CMake config module shipped by that package.
find_package(BDB REQUIRED)  # Local
find_package(GnuTLS REQUIRED)  # Module
find_package(GnuTLSDane REQUIRED)  # Local
find_package(Libldns REQUIRED)  # Local
find_package(LibTASN1 REQUIRED)  # Local
find_package(OpenLDAP REQUIRED)  # Local
find_package(P11-Kit REQUIRED)  # Local
find_package(Quick-DER 1.2.3 REQUIRED)  # Config
find_package(Unbound REQUIRED)  # Local

# TODO: look for Kerberos
# TODO: look for TLS-KDH

feature_summary(WHAT ALL VAR _features)
message(STATUS ${_features})

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
