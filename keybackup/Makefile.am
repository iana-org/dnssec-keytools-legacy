# $Id: Makefile.am 68 2010-02-10 13:13:00Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.log

COMMON =	$(srcdir)/../common
COMPAT =	$(srcdir)/../compat

AM_CPPFLAGS =	-I$(top_srcdir) \
		-I$(COMPAT) \
		-I$(COMMON) \
		-I$(COMMON)/cryptoki

bin_PROGRAMS = keybackup

keybackup_SOURCES = \
	keybackup.c \
	$(COMMON)/logger.c \
	$(COMMON)/mbuf.c \
	$(COMMON)/rlder.c \
	$(COMMON)/util.c
	
keybackup_LDFLAGS = -dl
keybackup_LDADD = libsha.a libcompat.a

noinst_LIBRARIES = libsha.a libcompat.a

libsha_a_SOURCES = $(COMMON)/sha1.c $(COMMON)/sha2.c
libsha_a_CFLAGS = -std=c99

libcompat_a_SOURCES = $(COMPAT)/strlcpy.c $(COMPAT)/strlcat.c
