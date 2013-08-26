# $Id: Makefile.am 62 2010-02-10 10:31:07Z jakob $

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

EXTRA_DIST = \
 	$(DX_CONFIG) \
	$(srcdir)/common/*.c \
	$(srcdir)/common/*.h \
	$(srcdir)/common/cryptoki/*.h \
	$(srcdir)/compat/*.c \
	$(srcdir)/compat/*.h

SUBDIRS = keybackup kskgen ksrsigner changepin checks utils

include doxygen.am

#doxygen:
#	INPUT=. PROJECT=$(PACKAGE_NAME) VERSION=$(VERSION) \
#	doxygen $(srcdir)/keytools.doxygen
