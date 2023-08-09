cmake_minimum_required(VERSION 3.18.4)
include(CheckSymbolExists)

set(CMAKE_VERBOSE_MAKEFILE ON)

project(
    ssldump
    VERSION 1.9
    LANGUAGES C
)

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

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules/")

find_package(OpenSSL REQUIRED)
find_package(PCAP REQUIRED)
find_package(LIBNET REQUIRED)
find_package(json-c REQUIRED)

add_executable(${PROJECT_NAME} ${SOURCES})

check_symbol_exists(strdup "string.h" HAVE_STRDUP)
if(HAVE_STRDUP)
    add_definitions(-DHAVE_STRDUP)
endif()

add_definitions(-DLINUX)
add_definitions(-DOPENSSL)
add_definitions(-D_DEFAULT_SOURCE=1)

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
        ${json-c_INCLUDE_DIR}
)

target_link_libraries(ssldump
    PRIVATE
        ${OPENSSL_LIBRARIES}
        pcap
        net
        json-c
)

