# Copyright (c) 2014, 2015 InternetWide.org and the ARPA2.net project
# All rights reserved. See file LICENSE for exact terms (2-clause BSD license).
#
# Adriaan de Groot <groot@kde.org>

# Try to find OpenLDAP client libraries. Sets standard variables
# OpenLDAP_LIBRARIES and OpenLDAP_INCLUDE_DIRS.
#
include(FindPackageHandleStandardArgs)

find_library(OpenLDAP_LIBRARY ldap)
find_library(OpenLDAP_BER_LIBRARY lber)

find_path(OpenLDAP_INCLUDE_DIR ldap.h)

find_package_handle_standard_args(OpenLDAP
    REQUIRED_VARS OpenLDAP_LIBRARY OpenLDAP_INCLUDE_DIR)
mark_as_advanced(OpenLDAP_LIBRARY OpenLDAP_BER_LIBRARY OpenLDAP_INCLUDE_DIR)

if(OpenLDAP_FOUND)
    set(OpenLDAP_LIBRARIES ${OpenLDAP_LIBRARY})
    if(OpenLDAP_LIBRARY AND OpenLDAP_BER_LIBRARY)
        list(APPEND OpenLDAP_LIBRARIES ${OpenLDAP_BER_LIBRARY})
    endif()

    set(OpenLDAP_INCLUDE_DIRS ${OpenLDAP_INCLUDE_DIR})
endif()



