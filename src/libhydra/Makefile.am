lib_LTLIBRARIES = libhydra.la

libhydra_la_SOURCES = \
hydra.c hydra.h \
attributes/attributes.c attributes/attributes.h \
attributes/attribute_provider.h attributes/attribute_handler.h \
attributes/attribute_manager.c attributes/attribute_manager.h \
attributes/mem_pool.c attributes/mem_pool.h

libhydra_la_LIBADD =

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DPLUGINDIR=\"${plugindir}\" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\"

EXTRA_DIST = Android.mk

# build optional plugins
########################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

if USE_ATTR
  SUBDIRS += plugins/attr
if MONOLITHIC
  libhydra_la_LIBADD += plugins/attr/libstrongswan-attr.la
endif
endif

if USE_ATTR_SQL
  SUBDIRS += plugins/attr_sql
if MONOLITHIC
  libhydra_la_LIBADD += plugins/attr_sql/libstrongswan-attr-sql.la
endif
endif

if USE_RESOLVE
  SUBDIRS += plugins/resolve
if MONOLITHIC
  libhydra_la_LIBADD += plugins/resolve/libstrongswan-resolve.la
endif
endif

