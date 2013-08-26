# $Id: ax_check_softhsm.m4 100 2010-03-25 20:54:38Z jakob $

AU_ALIAS([CHECK_SOFTHSM], [ACX_CHECK_SOFTHSM])
AC_DEFUN([ACX_CHECK_SOFTHSM],[
	AC_ARG_WITH(softhsm, 
		AS_HELP_STRING([--with-softhsm=PATH],[specify path for SoftHSM]),
		[ SOFTHSM_PATH="$withval" ],
		[ SOFTHSM_PATH="$prefix" ]
	)
	
	AC_MSG_CHECKING([for the SoftHSM PKCS11 provider])
        
	if test -f $SOFTHSM_PATH/lib/libsofthsm.so; then
		SOFTHSM_PROVIDER=$SOFTHSM_PATH/lib/libsofthsm.so
		AC_MSG_RESULT([$SOFTHSM_PROVIDER])
	else
		SOFTHSM_PROVIDER=
		AC_MSG_RESULT([no])
	fi

	AC_SUBST(SOFTHSM_PROVIDER)

	AC_PATH_PROG(SOFTHSM, softhsm)
])
