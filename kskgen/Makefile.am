# $Id: Makefile.am 64 2010-02-10 10:39:48Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.log

COMMON =	$(srcdir)/../common
COMPAT =	$(srcdir)/../compat

AM_CPPFLAGS =	-I$(top_srcdir) \
		-I$(COMPAT) \
		-I$(COMMON) \
		-I$(COMMON)/cryptoki

EXTRA_DIST =	$(srcdir)/*.h

bin_PROGRAMS = kskgen

kskgen_SOURCES = \
	kskgen.c \
	$(COMMON)/logger.c \
	$(COMMON)/mbuf.c \
	$(COMMON)/pkcs11_dnssec.c \
	$(COMMON)/rlder.c \
	$(COMMON)/base32.c \
	$(COMMON)/dnssec.c \
	$(COMMON)/util.c

kskgen_LDFLAGS = -dl
kskgen_LDADD = libsha.a libcompat.a

noinst_LIBRARIES = libsha.a libcompat.a

libsha_a_SOURCES = $(COMMON)/sha1.c $(COMMON)/sha2.c
libsha_a_CFLAGS = -std=c99

libcompat_a_SOURCES = $(COMPAT)/strlcpy.c $(COMPAT)/strlcat.c
