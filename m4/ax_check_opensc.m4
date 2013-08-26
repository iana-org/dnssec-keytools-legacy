# $Id: ax_check_opensc.m4 177 2010-05-07 14:16:54Z jakob $

AU_ALIAS([CHECK_OPENSC], [ACX_CHECK_OPENSC])
AC_DEFUN([ACX_CHECK_OPENSC],[
	AC_ARG_WITH(opensc, 
		AS_HELP_STRING([--with-opensc=PATH],[specify path for OpenSC]),
		[ OPENSC_PATH="$withval" ],
		[ OPENSC_PATH="$prefix" ]
	)
	
	AC_MSG_CHECKING([for the OpenSC])
        
	if test -f $OPENSC_PATH/lib/pkcs11-spy.so; then
		PKCS11SPY_PROVIDER=$OPENSC_PATH/lib/pkcs11-spy.so
		AC_MSG_RESULT([$PKCS11SPY_PROVIDER])
	else
		PKCS11SPY_PROVIDER=
		AC_MSG_RESULT([no])
	fi

	AC_SUBST(PKCS11SPY_PROVIDER)
])
