# ssldump - (de-facto repository gathering patches around the cyberspace)

[![Build CI](https://github.com/adulau/ssldump/actions/workflows/build.yml/badge.svg)](https://github.com/adulau/ssldump/actions/workflows/build.yml)
[![CodeQL analysis](https://github.com/adulau/ssldump/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/adulau/ssldump/actions/workflows/codeql-analysis.yml)

# Release and tagging

- Current version of ssldump is [v1.6](https://github.com/adulau/ssldump/releases/tag/v1.6) (released: 2023-02-03)
- Previous version of ssldump is [v1.5](https://github.com/adulau/ssldump/releases/tag/v1.5) (released: 2022-05-26) - [ChangeLog](https://raw.githubusercontent.com/adulau/ssldump/master/ChangeLog)

# What about the original ssldump?

This repository is composed of the original SSLDUMP 0.9b3 + a myriad of patches (from Debian and other distributions) + contributions via PR

ssldump is an SSLv3/TLS network protocol analyzer. It identifies TCP
connections on the chosen network interface and attempts to interpret
them as SSLv3/TLS traffic. When it identifies SSLv3/TLS traffic, it
decodes the records and displays them in a textual form to stdout. If
provided with the appropriate keying material, it will also decrypt
the connections and display the application data traffic. It also
includes a JSON output option, supports [JA3](https://github.com/salesforce/ja3) and IPv6.

# How to do I run ssldump?

`./ssldump  -j -ANH -n -i any | jq` will run ssldump on all interfaces and output the result in JSON format including ja3 hashes.

For more details, check the man page.

## How can I lookup ja3 hashes?

This example will query ja3er.com service to display the known ja3 hashes from the TLS handshaked in the pcap.

`ssldump -r yourcapture.pcap -j  | jq -r 'select(.ja3_fp != null) | .ja3_fp' | parallel 'curl -s -X GET 'https://ja3er.com/search/{}' | jq .'`

# Why do you maintain this repository?

Because it's a mess. The software maintenance process for old free (unmaintained) software
like ssldump is a complete chaotic process. I do this to ease my pain and this could help
other too (but this is just a collateral damage).

# Where ssldump is used?

- I used it for a relatively small project called Passive SSL. For more information, [Passive SSL Passive Detection and Reconnaissance Techniques, to Find, Track, and Attribute Vulnerable ”Devices”](https://www.first.org/resources/papers/conf2015/first_2015_-_leverett_-_dulaunoy_-_passive_detection_20150604.pdf). Additional back-end code available is in the [crl-monitor ](https://github.com/adulau/crl-monitor/tree/master/bin/x509) repository.
- ssldump is used in the [D4-Project](https://github.com/D4-project/).

# Build instructions

On Debian & Ubuntu:
```
apt install build-essential autoconf libssl-dev libpcap-dev libnet1-dev libjson-c-dev
./autogen.sh
./configure --prefix=/usr/local
make
(optional) make install
```

On Fedora, Centos & RHEL:
```
dnf install autoconf automake gcc make openssl-devel libpcap-devel libnet-devel json-c-devel
./autogen.sh
./configure --prefix=/usr/local
make
(optional) make install
```

Optional configuration features (aka ./configure options):
```
  --disable-optimization  disable compiler optimizations (change from -O2 to -O0)
  --enable-debug	  enable debug info (add "-g -DDEBUG" to CFLAGS)
  --enable-asan		  enable AddressSanitizer and other checks
	add "-fsanitize=address,undefined,leak -Wformat -Werror=format-security
		-Werror=array-bounds" to CFLAGS
	use libasan with GCC and embedded ASAN with Clang
```

Configuration examples:
```
- Use GCC with libasan, debug info and custom CFLAGS:
	./configure CC=/usr/bin/gcc --enable-asan --enable-debug CFLAGS="-Wall"

- Use Clang with ASAN and no optimizations (-O0)
	./configure CC=/usr/bin/clang --enable-asan --disable-optimization
```

# Notes

The "save to pcap" (-w) option by @ryabkov, is heavily based on the work of
@droe on https://github.com/droe/sslsplit .

# Contributing

The contributing policy is simple. If you have a patch to propose, make a pull-request
via the interface. If the patch works for me, it's merged.


