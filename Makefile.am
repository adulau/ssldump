bin_PROGRAMS = ssldump
man_MANS = ssldump.1

ssldump_SOURCES = \
	base/pcap-snoop.c\
	base/network.c\
	base/proto_mod.c\
	base/common.c\
	ssl/ssl_analyze.c\
	null/null_analyze.c\
	common/lib/r_data.c\
	common/lib/r_assoc.c\
	common/lib/r_errors.c\
	base/tcppack.c\
	base/tcpconn.c\
	ssl/ssldecode.c\
	ssl/sslprint.c\
	ssl/ssl.enums.c\
	ssl/sslxprint.c\
	ssl/ciphersuites.c\
	ssl/ssl_rec.c

ssldump_CPPFLAGS = \
	-I$(top_srcdir)\
	-I$(top_srcdir)/common/include\
	-I$(top_srcdir)/null\
	-I$(top_srcdir)/ssl\
	-I$(top_srcdir)/base\
	-D_DEFAULT_SOURCE=1\
	-DLINUX\
	-DOPENSSL
