ipsec_LTLIBRARIES = libchecksum.la
noinst_PROGRAMS = checksum_builder

nodist_libchecksum_la_SOURCES = checksum.c
libchecksum_la_LDFLAGS = -module -avoid-version

checksum_builder_SOURCES = checksum_builder.c
checksum_builder_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(DLLIB)

BUILT_SOURCES = checksum.c
CLEANFILES = checksum.c
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = -rdynamic

libs =	$(shell find $(top_builddir)/src/libstrongswan \
			$(top_builddir)/src/libcharon \
			$(top_builddir)/src/libhydra \
			$(top_builddir)/src/pluto \
			-name 'libstrongswan*.so')

if USE_LIBHYDRA
  libs += $(top_builddir)/src/libhydra/.libs/libhydra.so
endif

if USE_CHARON
  libs += $(top_builddir)/src/libcharon/.libs/libcharon.so
  libs += $(top_builddir)/src/charon/.libs/charon
endif

if USE_PLUTO
  libs += $(top_builddir)/src/pluto/.libs/pluto
endif

if USE_TOOLS
  libs += $(top_builddir)/src/openac/.libs/openac
  libs += $(top_builddir)/src/pki/.libs/pki
  libs += $(top_builddir)/src/scepclient/.libs/scepclient
endif

if USE_ATTR_SQL
  libs += $(top_builddir)/src/libhydra/plugins/attr_sql/.libs/pool
endif

checksum.c : checksum_builder $(libs)
		./checksum_builder $(libs) > checksum.c
