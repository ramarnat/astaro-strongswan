
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-serpent.la
else
plugin_LTLIBRARIES = libstrongswan-serpent.la
endif

libstrongswan_serpent_la_SOURCES = \
	serpent_plugin.h serpent_plugin.c serpent_crypter.c serpent_crypter.h \
	serpent.c serpent.h

libstrongswan_serpent_la_LDFLAGS = -module -avoid-version
