# $Id: acx_analyze.m4 134 2010-04-21 21:31:44Z jakob $

AC_DEFUN([ACX_ANALYZE],[
	AC_ARG_ENABLE(
		[analyze],
		[AS_HELP_STRING([--enable-analyze],[enable clang static analyzer  @<:@disabled@:>@])],
		,
		[enable_analyze="no"]
	)
	if test "${enable_analyze}" = "yes"; then
		CFLAGS="${CFLAGS} --analyze"
	fi
])
