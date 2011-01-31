## $Id$
# Process this file with autoconf to produce a configure script.

# $Id$

AC_PREREQ([2.64])
AC_INIT([dnsmole], [0.1], dns-mole@googlegroups.com)
AC_CONFIG_SRCDIR([src/dnsmole.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE
AC_PROG_CC_STDC
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_compile, , AC_MSG_ERROR(pcap libary required))
AC_CHECK_LIB(event, event_set, , AC_MSG_ERROR(event libary required))

# Checks for header files.
AC_CHECK_HEADERS([stdio.h math.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset memcpy sqrt strchr isalpha isdigit isuppser tolower strdup])

AC_CONFIG_FILES([Makefile include/Makefile man/Makefile src/Makefile src/methods/Makefile])
#AC_OUTPUT(Makefile src/Makefile include/Makefile doc/Makefile man/Makefile src/methods/Makefile)
AC_OUTPUT
