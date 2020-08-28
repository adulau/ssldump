#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ssldump], [1.1])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([base/pcap-snoop.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_INSTALL


# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h malloc.h memory.h netdb.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h],,[AC_MSG_ERROR([Missing header.])])
AC_HEADER_STDC
AC_HEADER_TIME

have_pcap=no
AC_SEARCH_LIBS([pcap_create], [pcap], [have_pcap=yes])

if test "x${have_pcap}" = xyes; then
	AC_CHECK_HEADERS([pcap.h pcap-bpf.h], [], [have_pcap=no])
fi

if test "x${have_pcap}" = xno; then
	AC_MSG_ERROR([
---------------------------------------
Unable to find libpcap on this system
Check 'config.log' for more information

On Debian and Ubuntu systems you can
install the required library and header
files with
  apt install libpcap-dev
---------------------------------------
	])
fi

AC_CHECK_LIB([pcap],[pcap_create])

have_ssl=no
AC_SEARCH_LIBS([OPENSSL_init_ssl], [ssl], [have_ssl=yes])

if test "x${have_ssl}" = xyes; then
	AC_CHECK_HEADERS([openssl/ssl.h], [], [have_ssl=no])
fi

if test "x${have_ssl}" = xno; then
	AC_MSG_ERROR([
---------------------------------------
Unable to find libssl on this system
Check 'config.log' for more information

On Debian and Ubuntu systems you can
install the required library and header
files with
  apt install libssl-dev
---------------------------------------
	])
fi

AC_CHECK_LIB([ssl], [OPENSSL_init_ssl])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_SIZEOF([unsigned short])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_SIZEOF([unsigned long long])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostbyaddr gettimeofday inet_ntoa isascii memmove memset strchr strdup strstr strtol])

AC_CONFIG_FILES([Makefile
                 common/Makefile
                 common/lib/Makefile
                 null/Makefile
                 ssl/Makefile
                 base/Makefile])
AC_OUTPUT
