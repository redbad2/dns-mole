#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT(dnsmole, 0.1, dns-mole@googlegroups.com)
AC_CONFIG_SRCDIR([include/query.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE(dnsmole, 0.1)

# Checks for programs.
AC_PROG_CC

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

AC_CONFIG_FILES([Makefile include/Makefile src/Makefile src/methods/Makefile])
#AC_OUTPUT(Makefile src/Makefile include/Makefile doc/Makefile man/Makefile src/methods/Makefile)
AC_OUTPUT
