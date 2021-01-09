#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ssldump], [1.1])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([base/pcap-snoop.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

# Checks for programs.
: ${CFLAGS=""}
AC_PROG_CC([gcc clang])
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_INSTALL

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h memory.h netdb.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h],,[AC_MSG_ERROR([Missing header.])])
AC_HEADER_STDC
AC_HEADER_TIME

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_SIZEOF([unsigned short])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_SIZEOF([unsigned long long])

# Checks for library functions.
AC_CHECK_FUNCS([malloc realloc gethostbyaddr gettimeofday inet_ntoa isascii memmove memset strchr strdup strstr strtol])

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

have_ssl=no
AC_SEARCH_LIBS([OPENSSL_init_ssl], [ssl], [have_ssl=yes])
AC_SEARCH_LIBS(CRYPTO_new_ex_data, [crypto], [have_crypto=yes])

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

have_libnet=no
AC_SEARCH_LIBS([libnet_init], [net], [have_libnet=yes])

if test "x${have_libnet}" = xyes; then
	AC_CHECK_HEADERS([libnet.h], [], [have_libnet=no])
fi

if test "x${have_libnet}" = xno; then
	AC_MSG_ERROR([
---------------------------------------
Unable to find libnet on this system
Check 'config.log' for more information

On Debian and Ubuntu systems you can
install the required library and header
files with
  apt install libnet1-dev
---------------------------------------
	])
fi

have_libjson_c=no
AC_SEARCH_LIBS([json_object_new_object], [json-c], [have_libjson_c=yes])

if test "x${have_libjson_c}" = xyes; then
	AC_CHECK_HEADERS([json-c/json.h], [], [have_libjson_c=no])
fi

if test "x${have_libjson_c}" = xno; then
	AC_MSG_ERROR([
---------------------------------------
Unable to find libjson-c on this system
Check 'config.log' for more information

On Debian and Ubuntu systems you can
install the required library and header
files with
  apt install libjson-c-dev
---------------------------------------
	])
fi

AC_ARG_ENABLE([optimization],
	[  --disable-optimization  disable compiler optimizations],
	[optimization=${enableval}], [optimization=yes])

if test "x${optimization}" = xno; then
	CFLAGS="$CFLAGS -O0"
else
	CFLAGS="$CFLAGS -O2"
fi

AC_ARG_ENABLE([debug],
	[  --enable-debug	  enable debug info],
	[debug=${enableval}], [debug=no])

if test "x${debug}" = xyes; then
	CFLAGS="$CFLAGS -g -DDEBUG"
fi

AC_ARG_ENABLE([asan],
	[  --enable-asan		  enable AddressSanitizer and other checks],
	[asan=${enableval}], [asan=no])

if test "x${asan}" = xyes; then
	AS_CASE([$CC],
	[*gcc*], [AC_CHECK_LIB(asan, _init)],
	[*clang*], [have_clang=yes],
        [have_clang=no])

	if (test "x${ac_cv_lib_asan__init}" = xyes || test "x$have_clang" = xyes); then
		CFLAGS="$CFLAGS \
-fsanitize=address,undefined,leak \
-Wformat \
-Werror=format-security \
-Werror=array-bounds"
	else
		AC_MSG_WARN("AddressSanitizer not supported")
		asan=no
	fi
fi

AC_CONFIG_FILES([Makefile
                 common/Makefile
                 common/lib/Makefile
                 null/Makefile
                 ssl/Makefile
                 pcap/Makefile
                 base/Makefile])

AC_OUTPUT

echo
echo "################################################"
echo "SSLDump build setup"
echo "	Host system:		$host_os"
echo "	Host architecture:	$host_cpu"
echo "	Compiler:		$CC"
echo "	Installation prefix:    $prefix"
echo "	CFLAGS:    		$CFLAGS"
echo "	LDFLAGS:    		$LDFLAGS"
echo "	LIBS:    		$LIBS"
echo "	Optimizations enabled:  $optimization"
echo "	Debug info enabled:	$debug"
echo "	ASAN enabled:		$asan"
echo "################################################"

