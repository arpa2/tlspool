# Finds the com_err support libraries and compiler
#
#  com_err_FOUND           - Set if compile_et is found
#  com_err_COMPILER        - Set to the compile_et compiler path
#  com_err_VERSION         - Set to the version of com_err
#  com_err_CFLAGS          - Set to the C compiler flags for com_err
#  com_err_LIBRARIES       - Set to the libraries for com_err
# 
# This module defines commands to expand the above lists:
# TODO: Or should this be a MacroXXX module?
#
#  add_com_err_table(errors EXTRA_SRC)
#
# which will fill ${EXTRA_SRC} with source files to include for the
# support of the error table in errors.et.
#
# The common usage pattern is:
#
#  add_com_err_table     (mycomplaints)
#  add_executable        (mysillyness silly.c ${COM_ERR_mycomplaints_SRC})
#  target_link_libraries (mysillyness ${com_err_LIBRARIES})
#
# In other modules, the same error table can be loaded and used in
# the same manner with
#
#  use_com_err_table     (mycomplaints)
#  add_executable        (mysillyness silly.c ${COM_ERR_mycomplaints_SRC})
#  target_link_libraries (mysillyness ${com_err_LIBRARIES})
#
# This adds a .et file from local source code.
#
include(FeatureSummary)

set_package_properties(com_err PROPERTIES
	DESCRIPTION "Find com_err development goodies"
	URL "https://docs.freebsd.org/info/com_err/com_err.pdf"
)

find_program (com_err_COMPILER
	NAMES "compile_et"
	)#DOC "Compiler for application-specific error code/message tables")

find_program (PKGCONFIG
	NAMES "pkg-config" "pkgconfig")

if (com_err_COMPILER AND PKGCONFIG)

	set (com_err_FOUND TRUE)

	exec_program (${PKGCONFIG}
			ARGS --version com_err
			OUTPUT_VARIABLE com_err_VERSION)

	exec_program (${PKGCONFIG}
			ARGS --cflags com_err
			OUTPUT_VARIABLE com_err_CFLAGS)

	exec_program (${PKGCONFIG}
			ARGS --libs com_err
			OUTPUT_VARIABLE com_err_LIBRARIES)

else()

	set (com_err_FOUND FALSE)

endif()

if (com_err_FOUND)
	if (NOT com_err_QUIETLY)
		message (STATUS "Found package com_err ${com_err_VERSION}")
		message (STATUS "Compiler definitions for com_err are \"${com_err_CFLAGS}\"")
		message (STATUS "Libraries for com_err linking are \"${com_err_LIBRARIES}\"")
		message (STATUS "The compiler for error code/message tables is \"${com_err_COMPILER}\"")
	endif ()
else()
	if (com_err_FIND_REQUIRED)
		message (FATAL_ERROR "Could not find REQUIRED package com_err")
	else()
		message (STATUS "Optional package com_err was not found")
	endif()
endif()

macro(use_com_err_table _tablename)
	add_compile_options (${com_err_CFLAGS})
	include_directories (${COM_ERR_${_tablename}_INCLUDE_DIRS})
endmacro()

macro(add_com_err_table _tablename)
	add_custom_command (OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.h ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.c
		COMMAND ${com_err_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/${_tablename}.et
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_tablename}.et
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	add_custom_target (error_table_${_tablename} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.h ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.c)
	set (COM_ERR_${_tablename}_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR})
	set (COM_ERR_${_tablename}_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
	set (COM_ERR_${_tablename}_SRC          ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.c)
	set (COM_ERR_${_tablename}_SRC          ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.c PARENT_SCOPE)
	use_com_err_table (${_tablename})
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${_tablename}.h DESTINATION include/tlspool)
endmacro()

