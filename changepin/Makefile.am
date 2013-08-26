# $Id: Makefile.am 68 2010-02-10 13:13:00Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

COMMON =	$(srcdir)/../common
COMPAT =	$(srcdir)/../compat

AM_CPPFLAGS =	-I$(top_srcdir) \
		-I$(COMPAT) \
		-I$(COMMON) \
		-I$(COMMON)/cryptoki

bin_PROGRAMS = changepin

changepin_SOURCES = \
	changepin.c

changepin_LDFLAGS = -dl
