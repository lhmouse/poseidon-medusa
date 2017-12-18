ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects

EXTRA_DIST = \
	etc/medusa2/main-template.conf	\
	etc/medusa2/medusa2-common-template.conf	\
	etc/medusa2/medusa2-primary-template.conf	\
	etc/medusa2/medusa2-secondary-template.conf

SUBDIRS = \
	medusa2-common	\
	medusa2-primary	\
	medusa2-secondary

pkginclude_HEADERS =

pkginclude_protocoldir = $(pkgincludedir)/protocol
pkginclude_protocol_HEADERS = \
	protocol/messages.hpp	\
	protocol/error_codes.hpp
