ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CPPFLAGS = -Wall -Wextra -Werror -Wsign-conversion -Wno-error=unused-parameter -Winvalid-pch	\
	-Wno-missing-field-initializers -Wwrite-strings -Wsuggest-attribute=noreturn -Wundef -Wshadow	\
	-Wstrict-aliasing=2 -Wstrict-overflow=2 -Wno-error=pragmas -pipe -fPIC -DPIC -pthread
AM_CXXFLAGS =
AM_LIBS =

EXTRA_DIST = \
	etc/poseidon-medusa2/poseidon-medusa2-secondary-template.conf

lib_LTLIBRARIES = \
	lib/libposeidon-medusa2-secondary.la

lib_libposeidon_medusa2_secondary_la_SOURCES = \
	src/mmain.cpp

lib_libposeidon_medusa2_secondary_la_LDFLAGS = \
	-no-undefined -version-info 0:0:0

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	etc/poseidon-medusa2/poseidon-medusa2-secondary-template.conf
