AM_CPPFLAGS = -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wno-error=unused-parameter	\
	-Winvalid-pch -Wno-missing-field-initializers -Wwrite-strings -Wsuggest-attribute=noreturn	\
	-Wundef -Wshadow -Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas	\
	-pipe -fPIC -DPIC -pthread
AM_CXXFLAGS = -Wnon-virtual-dtor
AM_LIBS =

pkgsysconfdir = ${sysconfdir}/@PACKAGE@
pkgsysconf_DATA =	\
	etc/medusa2/medusa2-primary-template.conf

pkginclude_HEADERS =

pkginclude_primarydir = ${pkgincludedir}/primary
pkginclude_primary_HEADERS =	\
	medusa2-primary/src/secondary_channel.hpp	\
	medusa2-primary/src/singletons/secondary_connector.hpp	\
	medusa2-primary/src/proxy_session.hpp	\
	medusa2-primary/src/singletons/proxy_server.hpp	\
	medusa2-primary/src/mmain.hpp

lib_LTLIBRARIES =	\
	lib/libmedusa2-primary.la

lib_libmedusa2_primary_la_SOURCES =	\
	medusa2-primary/src/secondary_channel.cpp	\
	medusa2-primary/src/singletons/secondary_connector.cpp	\
	medusa2-primary/src/proxy_session.cpp	\
	medusa2-primary/src/singletons/proxy_server.cpp	\
	medusa2-primary/src/mmain.cpp

lib_libmedusa2_primary_la_LDFLAGS =	\
	-Wl,--no-allow-shlib-undefined -module -version-info 0:0:0

lib_libmedusa2_primary_la_LIBADD =	\
	../medusa2-common/lib/libmedusa2-common.la	\
	-lposeidon-main
