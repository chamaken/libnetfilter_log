dnl Process this file with autoconf to create configure.

AC_INIT([libnetfilter_log], [1.0.1])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
	tar-pax no-dist-gzip dist-bzip2 1.6])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S

case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

AC_ARG_WITH([ipulog],
  AC_HELP_STRING([--without-ipulog], [don't build libipulog compat library]))
AM_CONDITIONAL([BUILD_IPULOG], [test "x$with_ipulog" != xno])

dnl Dependencies
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 0.0.41])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.2],
		  [HAVE_LNFCT=1], [HAVE_LNFCT=0])
AM_CONDITIONAL([BUILD_NFCT], [test "$HAVE_LNFCT" -eq 1])

dnl Output the makefile
AC_CONFIG_FILES([Makefile src/Makefile include/Makefile
	include/libnetfilter_log/Makefile utils/Makefile libnetfilter_log.pc
	doxygen.cfg])
AC_OUTPUT
