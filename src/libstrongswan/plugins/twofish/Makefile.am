
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-twofish.la
else
plugin_LTLIBRARIES = libstrongswan-twofish.la
endif

libstrongswan_twofish_la_SOURCES = \
	twofish_plugin.h twofish_plugin.c twofish_crypter.c twofish_crypter.h \
	twofish.c twofish.h

libstrongswan_twofish_la_LDFLAGS = -module -avoid-version
