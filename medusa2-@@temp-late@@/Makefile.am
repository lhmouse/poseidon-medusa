AM_CPPFLAGS = -Wall -Wextra -Wconversion -Wsign-conversion -Wno-error=unused	\
	-Winvalid-pch -Wwrite-strings -Wsuggest-attribute=noreturn -Wswitch-enum -Wundef -Wshadow	\
	-Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas -Wno-error=unknown-warning-option	\
	-pipe -fPIC -DPIC -pthread
AM_CXXFLAGS = -Wnon-virtual-dtor

pkgsysconfdir = ${sysconfdir}/@PACKAGE@
pkgsysconf_DATA =	\
	etc/medusa2/medusa2-@@temp-late@@-template.conf

pkginclude_HEADERS =

pkginclude_@@temp_late@@dir = ${pkgincludedir}/@@temp-late@@
pkginclude_@@temp_late@@_HEADERS =	\
	medusa2-@@temp-late@@/src/mmain.hpp

lib_LTLIBRARIES =	\
	lib/libmedusa2-@@temp-late@@.la

lib_libmedusa2_@@temp_late@@_la_SOURCES =	\
	medusa2-@@temp-late@@/src/mmain.cpp

lib_libmedusa2_@@temp_late@@_la_LDFLAGS =	\
	-Wl,--no-undefined -module -no-undefined -version-info 0:0:0

lib_libmedusa2_@@temp_late@@_la_LIBADD =	\
	../medusa2-common/lib/libmedusa2-common.la	\
	-lposeidon-main
