
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra -I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-pfroute.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-pfroute.la
endif

libstrongswan_kernel_pfroute_la_SOURCES = \
	kernel_pfroute_plugin.h kernel_pfroute_plugin.c \
	kernel_pfroute_net.h kernel_pfroute_net.c

libstrongswan_kernel_pfroute_la_LDFLAGS = -module -avoid-version
