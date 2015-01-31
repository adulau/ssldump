#  Copyright (C) 1999-2000 RTFM, Inc.
#  All Rights Reserved

#  This package is a SSLv3/TLS protocol analyzer written by Eric Rescorla
#  <ekr\@rtfm.com> and licensed by RTFM, Inc.

#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#  3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#  
#    This product includes software developed by Eric Rescorla for
#    RTFM, Inc.

#  4. Neither the name of RTFM, Inc. nor the name of Eric Rescorla may be
#    used to endorse or promote products derived from this
#    software without specific prior written permission.

#  THIS SOFTWARE IS PROVIDED BY ERIC RESCORLA AND RTFM, INC. ``AS IS'' AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH DAMAGE.
!IF "$(CFG)" == ""
CFG=release
!MESSAGE No configuration specified. Defaulting to release.
!ENDIF 

!IF "$(CFG)" != "release" && "$(CFG)" != "debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vcwin32.mak" CFG="debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "release"
!MESSAGE "debug"
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 


# Directories, relative to this one

ROOT=.
ANALYZE_SRCDIR=$(ROOT)\base
COMMONDIR=$(ROOT)\common
COMMON_LIB_SRCDIR=$(COMMONDIR)\lib
ANALYZE_NULL_SRCDIR=$(ROOT)\null
ANALYZE_SSL_SRCDIR=$(ROOT)\ssl

WIN32_DIR=$(ROOT)\win32
OBJ_DIR=$(ROOT)\out32
WINPCAP_DEV_DIR=$(WIN32_DIR)\WPdpack
WINPCAP_SRC_DIR=$(WIN32_DIR)\winpcap
WINPCAP_INCLUDES=-I$(WINPCAP_DEV_DIR)\include -I$(WINPCAP_DEV_DIR)\include\net \
-I$(WINPCAP_SRC_DIR)\wpcap\libpcap\win32\include

#
# OpenSSL-specific stuff
#

!IF "$(OPENSSL)" == ""
OPENSSL=no
!MESSAGE OpenSSL support defaulting to "no".
!ENDIF 

!IF "$(OPENSSL)" == "yes"

#
# Customize the next 3 macros match your openssl development setup
#
OPENSSL_DIR=$(ROOT)\..\openssl\openssl-0.9.6g
OPENSSL_RELEASE=$(OPENSSL_DIR)\out32
OPENSSL_DEBUG=$(OPENSSL_DIR)\out32.dbg

OPENSSL_DEFINES=/D OPENSSL
OPENSSL_RELEASE_LIBS=$(OPENSSL_RELEASE)\libeay32.lib $(OPENSSL_RELEASE)\ssleay32.lib
OPENSSL_DEBUG_LIBS=$(OPENSSL_DEBUG)\libeay32.lib $(OPENSSL_DEBUG)\ssleay32.lib
OPENSSL_INCLUDES=-I$(OPENSSL_DIR)\inc32

!ELSE  # no OpenSSL

OPENSSL_DEFINES=
OPENSSL_DIR=
OPENSSL_RELEASE=
OPENSSL_RELEASE_LIBS=
OPENSSL_DEBUG=
OPENSSL_DEBUG_LIBS=
OPENSSL_INCLUDES=

!ENDIF


PLATFORM=VC-WIN32
CC=cl.exe
LINK=link.exe

#
# Getting the C run-time flag correct is critical and difficult, sadly
# The same C run-time should be used by all the object code that comprises
# the process. This means all DLL's and static libs we link to must use the
# same C run-time, and we must match it with our flag.
# 
# the wpcap.dll is linked to the static C run-time lib, so we will also
#

C_RUNTIME_FLAG=/MT
COMMON_INCLUDES=-I$(ANALYZE_SRCDIR) -I$(COMMONDIR)\include -I$(COMMON_LIB_SRCDIR) -I$(ANALYZE_NULL_SRCDIR) \
-I$(ANALYZE_SSL_SRCDIR) -I$(WIN32_DIR) $(WINPCAP_INCLUDES) $(OPENSSL_INCLUDES)
COMMON_DEFINES=/D STDC /D WIN32 /D _CONSOLE \
	$(OPENSSL_DEFINES) /D STDC_HEADERS /D SIZEOF_UNSIGNED_SHORT=2 /D SIZEOF_UNSIGNED_LONG=4 \
	/D RETSIGTYPE=void /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4
COMMON_CFLAGS=/nologo /W3 $(COMMON_INCLUDES) $(COMMON_DEFINES) /Fp"$(OBJ_DIR)\ssldump.pch" /YX /Fd"$(OBJ_DIR)\\" /FD /c 
COMMON_LIBS=gdi32.lib Wsock32.lib $(WINPCAP_DEV_DIR)\lib\wpcap.lib
COMMON_LFLAGS=/nologo /subsystem:console /machine:I386 /opt:ref /incremental:no



# Set build-specific (i.e., release vs. debug) options

!IF  "$(CFG)" == "release"

BUILD_SPECIFIC_INCLUDES=
BUILD_SPECIFIC_DEFINES=/D NDEBUG
BUILD_SPECIFIC_CFLAGS=$(C_RUNTIME_FLAG) /O2 $(BUILD_SPECIFIC_INCLUDES) $(BUILD_SPECIFIC_DEFINES)
BUILD_SPECIFIC_LIBS=$(OPENSSL_RELEASE_LIBS)
BUILD_SPECIFIC_LFLAGS=

!ELSE  # =="debug"

BUILD_SPECIFIC_INCLUDES=
BUILD_SPECIFIC_DEFINES=/D _DEBUG 
BUILD_SPECIFIC_CFLAGS=$(C_RUNTIME_FLAG)d /ZI /Od /GZ $(BUILD_SPECIFIC_INCLUDES) $(BUILD_SPECIFIC_DEFINES)
BUILD_SPECIFIC_LIBS=$(OPENSSL_DEBUG_LIBS)
BUILD_SPECIFIC_LFLAGS=

!ENDIF

CFLAGS=$(COMMON_CFLAGS) $(BUILD_SPECIFIC_CFLAGS)
LFLAGS=$(COMMON_LFLAGS) $(BUILD_SPECIFIC_LFLAGS) $(COMMON_LIBS) $(BUILD_SPECIFIC_LIBS)



ALL : $(OBJ_DIR) "$(OBJ_DIR)\ssldump.exe"

"$(OBJ_DIR)" :
    if not exist "$(OBJ_DIR)/$(NULL)" mkdir "$(OBJ_DIR)"


CLEAN : 
	-@erase "$(OBJ_DIR)\debug.obj"
	-@erase "$(OBJ_DIR)\r_assoc.obj"
	-@erase "$(OBJ_DIR)\r_data.obj"
	-@erase "$(OBJ_DIR)\r_errors.obj"
	-@erase "$(OBJ_DIR)\r_list.obj"
	-@erase "$(OBJ_DIR)\r_replace.obj"
	-@erase "$(OBJ_DIR)\r_time.obj"
	-@erase "$(OBJ_DIR)\network.obj"
	-@erase "$(OBJ_DIR)\pcap-snoop.obj"
	-@erase "$(OBJ_DIR)\proto_mod.obj"
	-@erase "$(OBJ_DIR)\tcpconn.obj"
	-@erase "$(OBJ_DIR)\tcppack.obj"
	-@erase "$(OBJ_DIR)\null_analyze.obj"
	-@erase "$(OBJ_DIR)\ciphersuites.obj"
	-@erase "$(OBJ_DIR)\ssl.enums.obj"
	-@erase "$(OBJ_DIR)\ssl_analyze.obj"
	-@erase "$(OBJ_DIR)\ssl_rec.obj"
	-@erase "$(OBJ_DIR)\ssldecode.obj"
	-@erase "$(OBJ_DIR)\sslprint.obj"
	-@erase "$(OBJ_DIR)\sslxprint.obj"
	-@erase "$(OBJ_DIR)\ssldump.exe"


LINK_OBJS= \
	"$(OBJ_DIR)\debug.obj" \
	"$(OBJ_DIR)\r_assoc.obj" \
	"$(OBJ_DIR)\r_data.obj" \
	"$(OBJ_DIR)\r_errors.obj" \
	"$(OBJ_DIR)\r_list.obj" \
	"$(OBJ_DIR)\r_replace.obj" \
	"$(OBJ_DIR)\r_time.obj" \
	"$(OBJ_DIR)\network.obj" \
	"$(OBJ_DIR)\pcap-snoop.obj" \
	"$(OBJ_DIR)\proto_mod.obj" \
	"$(OBJ_DIR)\tcpconn.obj" \
	"$(OBJ_DIR)\tcppack.obj" \
	"$(OBJ_DIR)\null_analyze.obj" \
	"$(OBJ_DIR)\ciphersuites.obj" \
	"$(OBJ_DIR)\ssl.enums.obj" \
	"$(OBJ_DIR)\ssl_analyze.obj" \
	"$(OBJ_DIR)\ssl_rec.obj" \
	"$(OBJ_DIR)\ssldecode.obj" \
	"$(OBJ_DIR)\sslprint.obj" \
	"$(OBJ_DIR)\sslxprint.obj"

"$(OBJ_DIR)\ssldump.exe": "$(OBJ_DIR)" $(LINK_OBJS)
    $(LINK) @<<
	/OUT:$@ $(LFLAGS) $(LINK_OBJS)
<<


#
#    FILE DEPENDENCIES
#
#    file dependencies state, for each file that is built,
#    which file(s) it depends upon
#

$(OBJ_DIR)\debug.obj: $(COMMON_LIB_SRCDIR)\debug.h
$(OBJ_DIR)\debug.obj: $(COMMON_LIB_SRCDIR)\debug.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\debug.c

$(OBJ_DIR)\r_assoc.obj: $(COMMON_LIB_SRCDIR)\r_assoc.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_assoc.c

$(OBJ_DIR)\r_data.obj: $(COMMON_LIB_SRCDIR)\r_data.h
$(OBJ_DIR)\r_data.obj: $(COMMON_LIB_SRCDIR)\r_data.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_data.c

$(OBJ_DIR)\r_errors.obj: $(COMMON_LIB_SRCDIR)\r_errors.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_errors.c

$(OBJ_DIR)\r_list.obj: $(COMMON_LIB_SRCDIR)\r_list.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_list.c

$(OBJ_DIR)\r_replace.obj: $(COMMON_LIB_SRCDIR)\r_replace.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_replace.c

$(OBJ_DIR)\r_time.obj: $(COMMON_LIB_SRCDIR)\r_time.c
	$(CC) $(CFLAGS) /Fo$@ $(COMMON_LIB_SRCDIR)\r_time.c




$(OBJ_DIR)\network.obj: $(ANALYZE_SRCDIR)\network.h
$(OBJ_DIR)\network.obj: $(ANALYZE_SRCDIR)\network.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SRCDIR)\network.c

$(OBJ_DIR)\pcap-snoop.obj: $(ANALYZE_SRCDIR)\pcap-snoop.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SRCDIR)\pcap-snoop.c

$(OBJ_DIR)\proto_mod.obj: $(ANALYZE_SRCDIR)\proto_mod.h
$(OBJ_DIR)\proto_mod.obj: $(ANALYZE_SRCDIR)\proto_mod.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SRCDIR)\proto_mod.c

$(OBJ_DIR)\tcpconn.obj: $(ANALYZE_SRCDIR)\tcpconn.h
$(OBJ_DIR)\tcpconn.obj: $(ANALYZE_SRCDIR)\tcpconn.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SRCDIR)\tcpconn.c

$(OBJ_DIR)\tcppack.obj: $(ANALYZE_SRCDIR)\tcppack.h
$(OBJ_DIR)\tcppack.obj: $(ANALYZE_SRCDIR)\tcppack.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SRCDIR)\tcppack.c


$(OBJ_DIR)\null_analyze.obj: $(ANALYZE_NULL_SRCDIR)\null_analyze.h
$(OBJ_DIR)\null_analyze.obj: $(ANALYZE_NULL_SRCDIR)\null_analyze.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_NULL_SRCDIR)\null_analyze.c



$(OBJ_DIR)\ciphersuites.obj: $(ANALYZE_SSL_SRCDIR)\ciphersuites.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\ciphersuites.c

$(OBJ_DIR)\ssl.enums.obj: $(ANALYZE_SSL_SRCDIR)\ssl.enums.h
$(OBJ_DIR)\ssl.enums.obj: $(ANALYZE_SSL_SRCDIR)\ssl.enums.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\ssl.enums.c

$(OBJ_DIR)\ssl_analyze.obj: $(ANALYZE_SSL_SRCDIR)\ssl_analyze.h
$(OBJ_DIR)\ssl_analyze.obj: $(ANALYZE_SSL_SRCDIR)\ssl_analyze.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\ssl_analyze.c

$(OBJ_DIR)\ssl_rec.obj: $(ANALYZE_SSL_SRCDIR)\ssl_rec.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\ssl_rec.c

$(OBJ_DIR)\ssldecode.obj: $(ANALYZE_SSL_SRCDIR)\ssldecode.h
$(OBJ_DIR)\ssldecode.obj: $(ANALYZE_SSL_SRCDIR)\ssldecode.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\ssldecode.c

$(OBJ_DIR)\sslprint.obj: $(ANALYZE_SSL_SRCDIR)\sslprint.h
$(OBJ_DIR)\sslprint.obj: $(ANALYZE_SSL_SRCDIR)\sslprint.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\sslprint.c

$(OBJ_DIR)\sslxprint.obj: $(ANALYZE_SSL_SRCDIR)\sslxprint.h
$(OBJ_DIR)\sslxprint.obj: $(ANALYZE_SSL_SRCDIR)\sslxprint.c
	$(CC) $(CFLAGS) /Fo$@ $(ANALYZE_SSL_SRCDIR)\sslxprint.c
