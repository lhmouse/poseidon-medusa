AC_INIT([medusa2], [0.1], [lh_mouse@126.com])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_LANG([C++])

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT([disable-static dlopen])

AC_CONFIG_FILES([
	Makefile
	medusa2-common/Makefile
	medusa2-primary/Makefile
	medusa2-secondary/Makefile])
##_INSERT_NEW_MAKEFILE_HERE
AC_OUTPUT
