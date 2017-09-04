ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CPPFLAGS = -Wall -Wextra -Werror -Wsign-conversion -Wno-error=unused-parameter -Winvalid-pch	\
	-Wno-missing-field-initializers -Wwrite-strings -Wsuggest-attribute=noreturn -Wundef -Wshadow	\
	-Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas -pipe -fPIC -DPIC -pthread
AM_CXXFLAGS =
AM_LIBS =

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/medusa2/medusa2-secondary-template.conf

lib_LTLIBRARIES = \
	lib/libmedusa2-secondary.la

lib_libmedusa2_secondary_la_SOURCES = \
	src/primary_session.cpp	\
	src/singletons/primary_server.cpp	\
	src/mmain.cpp

lib_libmedusa2_secondary_la_LDFLAGS = \
	-module -no-undefined -version-info 0:0:0

lib_libmedusa2_secondary_la_LIBADD = \
	../medusa2-common/lib/libmedusa2-common.la
