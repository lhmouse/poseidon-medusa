AC_INIT([medusa2], [0.1], [lh_mouse@126.com])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_PROG_LIBTOOL
AC_LIBTOOL_DLOPEN

AC_CHECK_LIB([poseidon-main], [main], [], [echo "***** FIX THIS ERROR *****"; exit -2;])

AM_INIT_AUTOMAKE
LT_INIT

AC_CONFIG_FILES([
	Makefile
	medusa2-common/Makefile
	medusa2-primary/Makefile
	medusa2-secondary/Makefile
])
AC_OUTPUT
