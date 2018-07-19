AM_CPPFLAGS = -Wall -Wextra -Werror -Wconversion -Wsign-conversion	\
	-Winvalid-pch -Wno-missing-field-initializers -Wwrite-strings -Wsuggest-attribute=noreturn	\
	-Wundef -Wshadow -Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas	\
	-Wno-long-long -Wno-variadic-macros -Wno-error=unused-{function,variable,parameter}	\
	-pipe -fPIC -DPIC -pthread
AM_CXXFLAGS = -Wnon-virtual-dtor

%.hpp.gch: %.hpp ../config.h
	${AM_V_CXX}${CXX} -x c++-header ${DEFS} -I.. ${AM_CPPFLAGS} ${CPPFLAGS} ${AM_CXXFLAGS} ${CXXFLAGS} -Wno-error $< -o $@

BUILT_SOURCES =	\
	medusa2-common/src/precompiled.hpp.gch

CLEANFILES =	\
	medusa2-common/src/precompiled.hpp.gch

sysconf_DATA =

pkgsysconfdir = ${sysconfdir}/@PACKAGE@
pkgsysconf_DATA =	\
	etc/medusa2/main-template.conf	\
	etc/medusa2/medusa2-common-template.conf

pkginclude_HEADERS =

pkginclude_protocoldir = ${pkgincludedir}/protocol
pkginclude_protocol_HEADERS =	\
	../protocol/messages.hpp	\
	../protocol/error_codes.hpp

pkginclude_commondir = ${pkgincludedir}/common
pkginclude_common_HEADERS =	\
	medusa2-common/src/precompiled.hpp	\
	medusa2-common/src/encryption.hpp	\
	medusa2-common/src/mmain.hpp

lib_LTLIBRARIES =	\
	lib/libmedusa2-common.la

lib_libmedusa2_common_la_SOURCES =	\
	../protocol/messages.cpp	\
	medusa2-common/src/encryption.cpp	\
	medusa2-common/src/mmain.cpp

lib_libmedusa2_common_la_LDFLAGS =	\
	-Wl,--no-undefined -module -no-undefined -version-info 0:0:0

lib_libmedusa2_common_la_LIBADD =	\
	-lposeidon-main	\
	-lcrypto
