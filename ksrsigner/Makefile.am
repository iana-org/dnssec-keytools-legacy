# $Id: Makefile.am 72 2010-02-14 20:11:00Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.log

COMMON =	$(srcdir)/../common
COMPAT =	$(srcdir)/../compat

AM_CPPFLAGS =	-I$(top_srcdir) \
		-I$(COMPAT) \
		-I$(COMMON) \
		-I$(COMMON)/cryptoki

EXTRA_DIST =	$(srcdir)/*.h

bin_PROGRAMS = ksrsigner wksr

ksrsigner_SOURCES = \
	ksrsigner.c \
	ksrcommon.c \
	$(COMMON)/logger.c \
	$(COMMON)/mbuf.c \
	$(COMMON)/pkcs11_dnssec.c \
	$(COMMON)/rlder.c \
	$(COMMON)/base32.c \
	$(COMMON)/dnssec.c \
	$(COMMON)/util.c

ksrsigner_LDFLAGS = -dl
ksrsigner_LDADD = libsha.a libcompat.a

wksr_SOURCES = \
	wksr.c \
	ksrcommon.c \
	$(COMMON)/logger.c \
	$(COMMON)/mbuf.c \
	$(COMMON)/rlder.c \
	$(COMMON)/dnssec.c \
	$(COMMON)/util.c

wksr_CPPFLAGS = $(AM_CPPFLAGS) -I$(OPENSSL_INCLUDES)
wksr_LDFLAGS = $(OPENSSL_LDFLAGS) -lcrypto
wksr_LDADD = libsha.a libcompat.a

noinst_LIBRARIES = libsha.a libcompat.a

libsha_a_SOURCES = $(COMMON)/sha1.c $(COMMON)/sha2.c
libsha_a_CFLAGS = -std=c99

libcompat_a_SOURCES = $(COMPAT)/strlcpy.c $(COMPAT)/strlcat.c
