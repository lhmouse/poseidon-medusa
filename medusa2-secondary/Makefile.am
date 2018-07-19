AM_CPPFLAGS = -Wall -Wextra -Wconversion -Wsign-conversion -Wno-error=unused	\
	-Winvalid-pch -Wwrite-strings -Wsuggest-attribute=noreturn -Wswitch-enum -Wundef -Wshadow	\
	-Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas -Wno-error=unknown-warning-option	\
	-pipe -fPIC -DPIC -pthread
AM_CXXFLAGS = -Wnon-virtual-dtor

pkgsysconfdir = ${sysconfdir}/@PACKAGE@
pkgsysconf_DATA =	\
	etc/medusa2/medusa2-secondary-template.conf

pkginclude_HEADERS =

pkginclude_secondarydir = ${pkgincludedir}/secondary
pkginclude_secondary_HEADERS =	\
	medusa2-secondary/src/primary_session.hpp	\
	medusa2-secondary/src/singletons/primary_server.hpp	\
	medusa2-secondary/src/mmain.hpp

lib_LTLIBRARIES =	\
	lib/libmedusa2-secondary.la

lib_libmedusa2_secondary_la_SOURCES =	\
	medusa2-secondary/src/primary_session.cpp	\
	medusa2-secondary/src/singletons/primary_server.cpp	\
	medusa2-secondary/src/mmain.cpp

lib_libmedusa2_secondary_la_LDFLAGS =	\
	-Wl,--no-undefined -module -no-undefined -version-info 0:0:0

lib_libmedusa2_secondary_la_LIBADD =	\
	../medusa2-common/lib/libmedusa2-common.la	\
	-lposeidon-main
