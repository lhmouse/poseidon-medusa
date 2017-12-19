ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CPPFLAGS = -Wall -Wextra -Werror -Wsign-conversion -Wno-error=unused-parameter -Winvalid-pch	\
	-Wno-missing-field-initializers -Wwrite-strings -Wsuggest-attribute=noreturn -Wundef -Wshadow	\
	-Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas -pipe -fPIC -DPIC -pthread
AM_CXXFLAGS =
AM_LIBS =

%.hpp.gch: %.hpp
	$(CXX) -x c++-header @DEFS@ $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -Wno-error $< -o $@

BUILT_SOURCES = \
	src/precompiled.hpp.gch

CLEANFILES = \
	src/precompiled.hpp.gch

sysconf_DATA =

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/medusa2/main-template.conf	\
	etc/medusa2/medusa2-common-template.conf

pkginclude_HEADERS =

pkginclude_commondir = $(pkgincludedir)/common
pkginclude_common_HEADERS = \
	src/precompiled.hpp	\
	src/encryption.hpp	\
	src/mmain.hpp

lib_LTLIBRARIES = \
	lib/libmedusa2-common.la

lib_libmedusa2_common_la_SOURCES = \
	../protocol/messages.cpp	\
	src/encryption.cpp	\
	src/mmain.cpp

lib_libmedusa2_common_la_LDFLAGS = \
	-module -no-undefined -version-info 0:0:0
