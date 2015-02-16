#
# Autoconfiguration for the TLS Pool
#
AC_INIT([tlspool], [0.1], [rick@openfortress.nl])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror dist-bzip2])
LT_INIT

#
# Package configuration
#
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(
        [GNUTLS],
        [gnutls >= 3.2.21],
        [],
        [AC_MSG_ERROR([GnuTLS version 3.2.21 or later is missing])]
)

PKG_CHECK_MODULES(
        [P11KIT],
        [p11-kit-1 >= 0.22.1],
        [],
        [AC_MSG_ERROR([p11-kit version 0.22.1 or later is missing])]
)

PKG_CHECK_MODULES(
        [TASN1],
        [libtasn1],
        [],
        [AC_MSG_ERROR([libtasn1 is missing])]
)


#
# Compiler environment
#
AC_PROG_CC
#obsoleted by libtool# AC_PROG_RANLIB
#starting automake-1.12# AM_PROG_AR

AC_C_INLINE
if test "$ac_cv_c_inline" == no ; then
  AC_DEFINE(inline,)
  # AC_SUBST(HAVE_INLINE)
fi

AC_CHECK_HEADERS([arpa/inet.h], [], [AC_MSG_ERROR([<arpa/inet.h> is missing])])
AC_CHECK_HEADERS([fcntl.h], [], [AC_MSG_ERROR([<fcntl.h> is missing])])
AC_CHECK_HEADERS([memory.h], [], [AC_MSG_ERROR([<memory.h> is missing])])
AC_CHECK_HEADERS([netinet/in.h], [], [AC_MSG_ERROR([<netinet/in.h> is missing])])
AC_CHECK_HEADERS([stddef.h], [], [AC_MSG_ERROR([<stddef.h> is missing])])
AC_CHECK_HEADERS([stdint.h], [], [AC_MSG_ERROR([<stdint.h> is missing])])
AC_CHECK_HEADERS([stdlib.h], [], [AC_MSG_ERROR([<stdlib.h> is missing])])
AC_CHECK_HEADERS([string.h], [], [AC_MSG_ERROR([<string.h> is missing])])
AC_CHECK_HEADERS([sys/file.h], [], [AC_MSG_ERROR([<sys/file.h> is missing])])
AC_CHECK_HEADERS([sys/socket.h], [], [AC_MSG_ERROR([<sys/socket.h> is missing])])
AC_CHECK_HEADERS([syslog.h], [], [AC_MSG_ERROR([<syslog.h> is missing])])
AC_CHECK_HEADERS([unistd.h], [], [AC_MSG_ERROR([<unistd.h> is missing])])

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_FUNC_ALLOCA
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN

AC_CHECK_FUNCS([atexit], [], [AC_MSG_ERROR([atexit() is missing])])
AC_CHECK_FUNCS([bzero], [], [AC_MSG_ERROR([bzero() is missing])])
AC_CHECK_FUNCS([ftruncate], [], [AC_MSG_ERROR([ftruncate() is missing])])
AC_CHECK_FUNCS([getpass], [], [AC_MSG_ERROR([getpass() is missing])])
AC_CHECK_FUNCS([mkdir], [], [AC_MSG_ERROR([mkdir() is missing])])
AC_CHECK_FUNCS([socket], [], [AC_MSG_ERROR([socket() is missing])])
AC_CHECK_FUNCS([strcspn], [], [AC_MSG_ERROR([strcspn() is missing])])
AC_CHECK_FUNCS([strdup], [], [AC_MSG_ERROR([strdup() is missing])])
AC_CHECK_FUNCS([strerror], [], [AC_MSG_ERROR([strerror() is missing])])
AC_CHECK_FUNCS([strncasecmp], [], [AC_MSG_ERROR([strncasecmp() is missing])])
AC_CHECK_FUNCS([strrchr], [], [AC_MSG_ERROR([strrchr() is missing])])
AC_CHECK_FUNCS([strtol], [], [AC_MSG_ERROR([strtol() is missing])])
AC_CHECK_FUNCS([strtoul], [], [AC_MSG_ERROR([strtoul() is missing])])


#
# Iterate over versions of libdb and set BDB_LIBS to -ldbXXX; prefer default
#

AC_CHECK_LIB([db-4.0], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.0])])
AC_CHECK_LIB([db-4.1], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.1])])
AC_CHECK_LIB([db-4.2], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.2])])
AC_CHECK_LIB([db-4.3], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.3])])
AC_CHECK_LIB([db-4.4], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.4])])
AC_CHECK_LIB([db-4.5], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.5])])
AC_CHECK_LIB([db-4.6], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.6])])
AC_CHECK_LIB([db-4.7], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.7])])
AC_CHECK_LIB([db-4.8], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-4.8])])
AC_CHECK_LIB([db-5.0], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-5.0])])
AC_CHECK_LIB([db-5.1], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-5.1])])
AC_CHECK_LIB([db-5.2], [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb-5.2])])
AC_CHECK_LIB([db]    , [db_env_create], [AC_SUBST([BDB_LIBS], [-ldb]    )])

if [test "x${BDB_LIBS}" == "x" ]
then
	AC_MSG_ERROR([Failed to find a suitable BerkeleyDB library])
fi


#
# \shipout
#
AC_CONFIG_HEADERS([config.h])
#TODO# Left out: testdata/Makefile
AC_CONFIG_FILES([Makefile src/Makefile lib/Makefile tool/Makefile])
AC_OUTPUT
