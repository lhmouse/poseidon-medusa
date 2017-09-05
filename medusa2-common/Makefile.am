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

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/medusa2/main-template.conf	\
	etc/medusa2/medusa2-common-template.conf

pkginclude_protocoldir = $(pkgincludedir)/protocol
pkginclude_protocol_HEADERS = \
	protocol/messages_fwd.hpp	\
	protocol/messages.hpp	\
	protocol/error_codes.hpp

lib_LTLIBRARIES = \
	lib/libmedusa2-common.la

lib_libmedusa2_common_la_SOURCES = \
	src/encryption.cpp	\
	src/mmain.cpp

lib_libmedusa2_common_la_LDFLAGS = \
	-module -no-undefined -version-info 0:0:0
