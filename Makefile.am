bin_PROGRAMS = ssldump
man_MANS = ssldump.1

ssldump_SOURCES = \
	base/pcap-snoop.c\
	base/network.c\
	base/proto_mod.c\
	base/tcppack.c\
	base/tcpconn.c\
	null/null_analyze.c\
	common/lib/r_data.c\
	common/lib/r_assoc.c\
	common/lib/r_errors.c\
	common/lib/debug.c\
	ssl/ssl_analyze.c\
	ssl/ssldecode.c\
	ssl/sslprint.c\
	ssl/ssl.enums.c\
	ssl/sslxprint.c\
	ssl/ciphersuites.c\
	ssl/ssl_rec.c\
	pcap/logpkt.c\
	pcap/pcap_logger.c\
	pcap/sys.c


ssldump_CPPFLAGS = \
	-I$(top_srcdir)\
	-I$(top_srcdir)/common/include\
	-I$(top_srcdir)/common/lib\
	-I$(top_srcdir)/null\
	-I$(top_srcdir)/ssl\
	-I$(top_srcdir)/base\
	-I$(top_srcdir)/pcap\
	-D_DEFAULT_SOURCE=1\
	-DLINUX\
	-DOPENSSL
