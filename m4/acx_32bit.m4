# $Id: acx_64bit.m4 2797 2010-02-09 08:23:22Z rb $

AC_DEFUN([ACX_32BIT],[
	AC_ARG_ENABLE(
	        [32bit],
        	[AS_HELP_STRING([--enable-32bit],[enable 32-bit compiling])],
	        [enable_32bit="${enableval}"],
	        [enable_32bit="no"])

	if test "x$enable_32bit" = "xyes"
	then
	        AC_MSG_CHECKING(if we can compile in 32-bit mode)
	        tmp_CFLAGS=$CFLAGS
	        CFLAGS="-m32"
	        AC_RUN_IFELSE(
	                [
				AC_LANG_PROGRAM([],[return sizeof(void*) == 4 ? 0 : 1;])
			], [
	                        AC_MSG_RESULT(yes)
	                        CXXFLAGS="-m32 $CXXFLAGS"
	                        LDFLAGS="-m32 $LDFLAGS"
	                        CFLAGS="-m32 $tmp_CFLAGS"
	                ],[
	                        AC_MSG_RESULT(no)
	                        AC_MSG_ERROR([Don't know how to compile in 32-bit mode.])
	        		CFLAGS=$tmp_CFLAGS
	                ]
	        )
	fi

])
