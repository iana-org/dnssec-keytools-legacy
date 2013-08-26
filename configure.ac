# $Id: configure.ac 73 2010-02-24 22:35:38Z jakob $

m4_sinclude([version.m4])

AC_PREREQ(2.59)
AC_INIT([icann-keytools], KEYTOOLS_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_SRCDIR([keybackup/keybackup.c])
AC_CONFIG_SRCDIR([kskgen/pkcs11-genksk.c])
AC_CONFIG_SRCDIR([ksrsigner/ksrsigner.c])

AC_CONFIG_HEADER([config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_PEDANTIC
ACX_STRICT
ACX_ANALYZE

ACX_32BIT
ACX_64BIT

# Checks for libraries. 
AC_CHECK_LIB([dl], [dlopen])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getpass getpassphrase])
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(strlcat)

CHECK_SSL
CHECK_SOFTHSM
CHECK_OPENSC

AC_PATH_PROG(OPENSSL, openssl)

DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(${PACKAGE_NAME}, [Doxyfile], [doxygen-doc])

AC_CONFIG_FILES([
	Makefile
	keybackup/Makefile
	kskgen/Makefile
	ksrsigner/Makefile
	changepin/Makefile
	checks/Makefile
	utils/Makefile
	Doxyfile
])

if test -n "${SOFTHSM_PROVIDER}"; then
        AC_CONFIG_FILES([checks/softhsm.hsmconfig])
fi

if test -n "${PKCS11SPY_PROVIDER}"; then
	AC_CONFIG_FILES([checks/pkcs11spy.hsmconfig])
fi

AC_OUTPUT
