
AM_CPPFLAGS = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=squidscas.la

DEFS = @DEFS@
OBJDIR = @OBJDIR@

squidscas_la_LIBADD = @MODULES_LIBADD@
squidscas_la_LDFLAGS= -module -avoid-version
squidscas_la_CFLAGS=  -I../../include/ @HAVE_TEMPLATE@ @HAVE_HASALLDATA@ @HAVE_ARCHIVE@ -DCONFIGDIR=\"$(CONFIGDIR)\"
squidscas_la_SOURCES = squidscas.c

EXTRA_DIST = squidscas.h
