# ssldump - (de-facto repository gathering patches around the cyberspace)

[![Build CI](https://github.com/adulau/ssldump/actions/workflows/build.yml/badge.svg)](https://github.com/adulau/ssldump/actions/workflows/build.yml)
[![CodeQL analysis](https://github.com/adulau/ssldump/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/adulau/ssldump/actions/workflows/codeql-analysis.yml)

# Release and tagging

- Current version of ssldump is [v1.7](https://github.com/adulau/ssldump/releases/tag/v1.7) (released: 2023-04-09) - [ChangeLog](https://raw.githubusercontent.com/adulau/ssldump/master/ChangeLog)

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

`./ssldump -j -ANH -n -i any | jq` will run ssldump on all interfaces and output the result in JSON format including ja3 hashes.

For more details, check the man page.

## How can I lookup ja3 hashes?

This example will query ja3er.com service to display the known ja3 hashes from the TLS handshaked in the pcap.

`ssldump -r yourcapture.pcap -j | jq -r 'select(.ja3_fp != null) | .ja3_fp' | parallel 'curl -s -X GET 'https://ja3er.com/search/{}' | jq .'`

# Why do you maintain this repository?

Because it's a mess. The software maintenance process for old free (unmaintained) software
like ssldump is a complete chaotic process. I do this to ease my pain and this could help
other too (but this is just a collateral damage).

# Where ssldump is used?

- I used it for a relatively small project called Passive SSL. For more information, [Passive SSL Passive Detection and Reconnaissance Techniques, to Find, Track, and Attribute Vulnerable ”Devices”](https://www.first.org/resources/papers/conf2015/first_2015_-_leverett_-_dulaunoy_-_passive_detection_20150604.pdf). Additional back-end code available is in the [crl-monitor ](https://github.com/adulau/crl-monitor/tree/master/bin/x509) repository.
- ssldump is used in the [D4-Project](https://github.com/D4-project/).

# Where ssldump is available? 

- Alpine Linux [ssldump](https://pkgs.alpinelinux.org/packages?name=ssldump&branch=edge&repo=&arch=&maintainer=)
- Arch Linux [ssldump](https://aur.archlinux.org/packages/ssldump)
- CentOS, RHEL, Rocky (via [EPEL](https://docs.fedoraproject.org/en-US/epel/)) [ssldump](https://packages.fedoraproject.org/pkgs/ssldump/ssldump/)
- Fedora [ssldump](https://packages.fedoraproject.org/pkgs/ssldump/ssldump/)
- Kali Linux [ssldump](https://www.kali.org/tools/ssldump/)
- Ubuntu Linux [ssldump](http://changelogs.ubuntu.com/changelogs/pool/universe/s/ssldump/)

# Build instructions

Install dependencies on Debian & Ubuntu (as root):
```
apt install build-essential git cmake ninja-build libssl-dev libpcap-dev libnet1-dev libjson-c-dev
```

On Fedora, CentOS, RHEL & Rocky (as root):
```
dnf install git cmake ninja-build gcc openssl-devel libpcap-devel libnet-devel json-c-devel
```

On OpenBSD (as root):
```
pkg_add git cmake ninja json-c libnet
```

On FreeBSD (as root):
```
pkg install git cmake ninja json-c libnet
```

On MacOS (as root):
```
brew install cmake ninja openssl@3 libpcap libnet json-c
```

Compile & install:
```
git clone https://github.com/adulau/ssldump.git
cd ssldump
cmake -G Ninja -B build
ninja -C build
./build/ssldump -v
(optional, as root) ninja -C build install
```

# Notes

The "save to pcap" (-w) option by @ryabkov, is heavily based on the work of
@droe on https://github.com/droe/sslsplit .

# Contributing

The contributing policy is simple. If you have a patch to propose, make a pull-request
via the interface. If the patch works for me, it's merged.


