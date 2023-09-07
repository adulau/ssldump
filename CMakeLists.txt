cmake_minimum_required(VERSION 3.13.4)

project(
    ssldump
    VERSION 1.8
    DESCRIPTION 20230814
    LANGUAGES C
)

include(CheckSymbolExists)
include(GNUInstallDirs)

configure_file(base/pcap-snoop.c.in base/pcap-snoop.c)

set(SOURCES
	${CMAKE_BINARY_DIR}/base/pcap-snoop.c
	base/network.c
	base/proto_mod.c
	base/tcppack.c
	base/tcpconn.c
	null/null_analyze.c
	common/lib/r_data.c
	common/lib/r_assoc.c
	common/lib/r_errors.c
	common/lib/debug.c
	ssl/ssl_analyze.c
	ssl/ssldecode.c
	ssl/sslprint.c
	ssl/ssl.enums.c
	ssl/sslxprint.c
	ssl/ciphersuites.c
	ssl/ssl_rec.c
	pcap/logpkt.c
	pcap/pcap_logger.c
	pcap/sys.c
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules/" ${CMAKE_MODULE_PATH})

find_package(OpenSSL)
if(NOT OPENSSL_FOUND)
    message( FATAL_ERROR
"Unable to find OpenSSL development files on this system
On Debian and Ubuntu systems you can install the required library and header files with
    apt install libssl-dev
On Fedora systems, with
    dnf install openssl-devel" )
endif()

#dnf install openssl-devel libpcap-devel libnet-devel json-c-devel

find_package(PCAP)
if(NOT PCAP_FOUND)
    message( FATAL_ERROR
"Unable to find libpcap development files on this system
On Debian and Ubuntu systems you can install the required library and header files with
    apt install libpcap-dev
On Fedora systems, with
    dnf install libpcap-devel" )
endif()

find_package(LIBNET)
if(NOT LIBNET_FOUND)
    message( FATAL_ERROR
"Unable to find libnet development files on this system
On Debian and Ubuntu systems you can install the required library and header files with
    apt install libnet1-dev
On Fedora systems, with
    dnf install libnet-devel" )
endif()

find_package(JSONC)
if(NOT JSONC_FOUND)
    message( FATAL_ERROR
"Unable to find libjson-c development files on this system
On Debian and Ubuntu systems you can install the required library and header files with
    apt install libjson-c-dev
On Fedora systems, with
    dnf install json-c-devel" )
endif()

add_executable(${PROJECT_NAME} ${SOURCES})

check_symbol_exists(strdup "string.h" HAVE_STRDUP)
if(HAVE_STRDUP)
    add_definitions(-DHAVE_STRDUP)
endif()

add_definitions(-DLINUX)
add_definitions(-DOPENSSL)
add_definitions(-D_DEFAULT_SOURCE=1)

set(CMAKE_C_FLAGS "-g")

target_include_directories(ssldump
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/common/include
        ${PROJECT_SOURCE_DIR}/common/lib
        ${PROJECT_SOURCE_DIR}/null
        ${PROJECT_SOURCE_DIR}/ssl
        ${PROJECT_SOURCE_DIR}/base
        ${PROJECT_SOURCE_DIR}/pcap
        ${OPENSSL_INCLUDE_DIR}
        ${PCAP_INCLUDE_DIR}
        ${LIBNET_INCLUDE_DIR}
        ${JSONC_INCLUDE_DIR}
)

target_link_libraries(ssldump
    PRIVATE
        ${OPENSSL_LIBRARIES}
        ${PCAP_LIBRARY}
        ${LIBNET_LIBRARY}
        ${JSONC_LIBRARIES}
)

install(TARGETS ssldump DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ssldump.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
