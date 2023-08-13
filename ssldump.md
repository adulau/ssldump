# ssldump(1) - dump SSL traffic on a network

9th April 2023 - version 1.7

```
.na ssldump [ -aAdeFHjnNPqtTvxXyz ] [ -i interface ]
.ti +8 [ -k keyfile ] [ -l sslkeylogfile ] [ -p password ] [ -r dumpfile ] [ -w outputpcap ]
.ti +8 [ -S [ crypto | d | ht | H | nroff ] ] [ expression ]

```

<a name="description"></a>

# Description


_ssldump_ is an SSL/TLS network protocol analyzer. It identifies
TCP connections on the chosen network interface and attempts to
interpret them as SSL/TLS traffic. When it identifies SSL/TLS
traffic, it decodes the records and displays them in a textual
form to stdout. If provided with the appropriate keying material,
it will also decrypt the connections and display the application
data traffic.  It supports various version of SSL/TLS up to TLS version 1.3.
It also includes support for JSON output or JA3 support.

_ssldump_ has been originally tested on FreeBSD, Linux, Solaris, and HP/UX. _ssldump_ has
mainly a new build process and it's mainly tested on different Linux flavors. Since
it's based on PCAP, it should work on most platforms. However, unlike
tcpdump, _ssldump_ needs to be able to see both sides of the data
transmission so you may have trouble using it with network taps such
as SunOS nit that don't permit you to see transmitted data.
**Under SunOS with nit or bpf:**
To run
_ssldump_
you must have read access to
_/dev/nit_
or
_/dev/bpf*_.
**Under Solaris with dlpi:**
You must have read access to the network pseudo device, e.g.
_/dev/le_.
**Under HP-UX with dlpi:**
You must be root or it must be installed setuid to root.
**Under IRIX with snoop:**
You must be root or it must be installed setuid to root.
**Under Linux:**
You must be root or it must be installed setuid to root.
**Under Ultrix and Digital UNIX:**
Once the super-user has enabled promiscuous-mode operation using
_pfconfig_(8),
any user may run
_ssldump_
**Under BSD:**
You must have read access to
_/dev/bpf*_.

<a name="options"></a>

# Options


* **-a**  
  Print bare TCP ACKs (useful for observing Nagle behavior).
* **-A**  
  Print all record fields (by default _ssldump_ chooses
  the most interesting fields).
* **-d**  
  Display the application data traffic. This usually means
  decrypting it, but when -d is used _ssldump_ will also decode
  application data traffic _before_ the SSL session initiates.
  This allows you to see HTTPS CONNECT behavior as well as
  SMTP STARTTLS. As a side effect, since _ssldump_ can't tell
  whether plaintext is traffic before the initiation of an
  SSL connection or just a regular TCP connection, this allows
  you to use _ssldump_ to sniff any TCP connection.
  _ssldump_ will automatically detect ASCII data and display it
  directly to the screen. non-ASCII data is displayed as hex
  dumps. See also -X.
* **-e**  
  Print absolute timestamps instead of relative timestamps.
* **-F**  
  Specify the number of packets after which a connection pool cleaning is performed (in packets, default: 100).
* **-H**  
  Print the full SSL packet header.
* **-i** _interface_  
  Use _interface_ as the network interface on which to sniff SSL/TLS
  traffic.
* **-j**  
  Switch output format to JSON. Only stdout is affected by this toggle.
* **-k** _keyfile_  
  Use _keyfile_ as the location of the SSL keyfile (OpenSSL format)
  Previous versions of _ssldump_ automatically looked in ./server.pem.
  Now you must specify your keyfile every time.
* **-l** _sslkeylogfile_  
  Use _sslkeylogfile_ as the location of the SSLKEYLOGFILE
  (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
* **-n**  
  Don't try to resolve host names from IP addresses.
* **-N**  
  Attempt to parse ASN.1 when it appears, such as in
  certificates and DNs.
* **-p** _password_  
  Use _password_ as the SSL keyfile password.
* **-P**  
  Don't put the interface into promiscuous mode.
* **-q**  
  Don't decode any record fields beyond a single summary line. (quiet mode).
* **-r** _file_  
  Read data from _file_ instead of from the network.
  The old -f option still works but is deprecated and will
  probably be removed with the next version.
* **-S** _[_ **crypto** _|_ **d** _|_ **ht** _|_ **H** _]_  
  Specify SSL flags to _ssldump_.  These flags include:
    * _crypto_  
      Print cryptographic information.
    * _d_  
      Print fields as decoded.
    * _ht_  
      Print the handshake type.
    * _H_  
      Print handshake type and highlights.
* **-t**  
  Specify the TTL for inactive connections referenced in the connection pool (in seconds, default: 100).
* **-T**  
  Print the TCP headers.
* **-v**  
  Display version and copyright information.
* **-w** _outputpcap_  
  Use _outputpcap_ as the destination for decrypted packets.
* **-x**  
  Print each record in hex, as well as decoding it.
* **-X**  
  When the -d option is used, binary data is automatically printed
  in two columns with a hex dump on the left and the printable characters
  on the right. -X suppresses the display of the printable characters,
  thus making it easier to cut and paste the hex data into some other
  program.
* **-y**  
  Decorate the output for processing with nroff/troff. Not very
  useful for the average user.
* **-z**
  Add timestamp in front of TCP packet description (-T)
* _expression_  
      Selects what packets _ssldump_ will examine. Technically speaking,
      _ssldump_ supports the full expression syntax from PCAP and tcpdump.
      In fact, the description here is cribbed from the tcpdump man
      page. However, since _ssldump_ needs to examine full TCP streams,
      most of the tcpdump expressions will select traffic mixes
      that _ssldump_ will simply ignore. Only the expressions which
      don't result in incomplete TCP streams are listed here. 

The _expression_ consists of one or more
_primitives_.
Primitives usually consist of an
_id_
(name or number) preceded by one or more qualifiers.  There are three
different kinds of qualifier:

* _type_  
  qualifiers say what kind of thing the id name or number refers to.
  Possible types are
  **host**,
  **net**
  and
  **port**.
  E.g., \`host foo', \`net 128.3', \`port 20'.  If there is no type
  qualifier,
  **host**
  is assumed.
* _dir_  
  qualifiers specify a particular transfer direction to and/or from
  _id._
  Possible directions are
  **src**,
  **dst**,
  **src or dst**
  and
  **src and**
  **dst**.
  E.g., \`src foo', \`dst net 128.3', \`src or dst port ftp-data'.  If
  there is no dir qualifier,
  **src or dst**
  is assumed.
  For \`null' link layers (i.e. point to point protocols such as slip) the
  **inbound**
  and
  **outbound**
  qualifiers can be used to specify a desired direction.

More complex filter expressions are built up by using the words
**and**,
**or**
and
**not**
to combine primitives.  E.g., \`host foo and not port ftp and not port ftp-data'.
To save typing, identical qualifier lists can be omitted.  E.g.,
\`tcp dst port ftp or ftp-data or domain' is exactly the same as
\`tcp dst port ftp or tcp dst port ftp-data or tcp dst port domain'.

Allowable primitives are:

* **dst host host**  
  True if the IPv4/v6 destination field of the packet is _host_,
  which may be either an address or a name.
* **src host host**  
  True if the IPv4/v6 source field of the packet is _host_.
* True if either the IPv4/v6 source or destination of the packet is _host_.
  Any of the above host expressions can be prepended with the keywords,
  **ip**, **arp**, **rarp**, or **ip6** as in:
    ip host host
  which is equivalent to:
    ether proto \ip and host host
  If _host_ is a name with multiple IP addresses, each address will
  be checked for a match.
* True if the ethernet destination address is _ehost_.  _Ehost_
  may be either a name from /etc/ethers or a number (see
  _ethers_(3N)
  for numeric format).
* True if the ethernet source address is _ehost_.
* True if either the ethernet source or destination address is _ehost_.
* True if the packet used _host_ as a gateway.  I.e., the ethernet
  source or destination address was _host_ but neither the IP source
  nor the IP destination was _host_.  _Host_ must be a name and
  must be found in both /etc/hosts and /etc/ethers.  (An equivalent
  expression is
    ether host ehost and not host host
  which can be used with either names or numbers for _host / ehost_.)
  This syntax does not work in IPv6-enabled configuration at this moment.
* **dst net net**  
  True if the IPv4/v6 destination address of the packet has a network
  number of _net_. _Net_ may be either a name from /etc/networks
  or a network number (see _networks(4)_ for details).
* **src net net**  
  True if the IPv4/v6 source address of the packet has a network
  number of _net_.
* **net net**  
  True if either the IPv4/v6 source or destination address of the packet has a network
  number of _net_.
* **net net** **mask mask**  
  True if the IP address matches _net_ with the specific netmask.
  May be qualified with **src** or **dst**.
  Note that this syntax is not valid for IPv6 _net_.
* **net _net**/len_  
  True if the IPv4/v6 address matches _net_ a netmask _len_ bits wide.
  May be qualified with **src** or **dst**.
* **dst port port**  
  True if the packet is ip/tcp, ip/udp, ip6/tcp or ip6/udp and has a
  destination port value of _port_.
  The _port_ can be a number or a name used in /etc/services (see
  _tcp_(4P)
  and
  _udp_(4P)).
  If a name is used, both the port
  number and protocol are checked.  If a number or ambiguous name is used,
  only the port number is checked (e.g., **dst port 513** will print both
  tcp/login traffic and udp/who traffic, and **port domain** will print
  both tcp/domain and udp/domain traffic).
* **src port port**  
  True if the packet has a source port value of _port_.
* **port port**  
  True if either the source or destination port of the packet is _port_.
  Any of the above port expressions can be prepended with the keywords,
  **tcp** or **udp**, as in:
    tcp src port port
  which matches only tcp packets whose source port is _port_.

Primitives may be combined using:

* A parenthesized group of primitives and operators
  (parentheses are special to the Shell and must be escaped).
* Negation (\`**!**' or \`**not**').
* Concatenation (\`**&&**' or \`**and**').
* Alternation (\`**||**' or \`**or**').

Negation has highest precedence.
Alternation and concatenation have equal precedence and associate
left to right.  Note that explicit **and** tokens, not juxtaposition,
are now required for concatenation.

If an identifier is given without a keyword, the most recent keyword
is assumed.
For example,
    not host vs and ace
is short for
    not host vs and host ace
which should not be confused with
    not ( host vs or ace )

Expression arguments can be passed to _ssldump_ as either a single argument
or as multiple arguments, whichever is more convenient.
Generally, if the expression contains Shell metacharacters, it is
easier to pass it as a single, quoted argument.
Multiple arguments are concatenated with spaces before being parsed.

<a name="examples"></a>

# Examples


To listen to traffic on interface _le0_ port _443_:
    ssldump -i le0 port 443

To listen to traffic to the server _romeo_ on port _443_:
    ssldump -i le0 port 443 and host romeo:

To switch output format to JSON:
    ssldump -ANH -j -i le0 port 443 and host romeo

To decrypt traffic to host _romeo_ 
_server.pem_ and the password _foobar_:
    ssldump -Ad -k ~/server.pem -p foobar -i le0 host romeo

<a name="output-format"></a>

# Output Format


All output is printed to standard out.

_ssldump_ prints an indication of every new TCP connection using a line
like the following
    
    New TCP connection #2: iromeo.rtfm.com(2302) <-> sr1.rtfm.com(4433)
    
The host which send the first SYN is printed on the left and the host
which responded is printed on the right. Ordinarily, this means that
the SSL client will be printed on the left with the SSL server on the
right. In this case we have a connection from _iromeo.rtfm.com_ (port _2303_)
to _sr1.rtfm.com_ (port _4433_). To allow the user to disentangle
traffic from different connections, each connection is numbered. This is
connection _2_.

The printout of each SSL record begins with a record line. This
line contains the connection and record number, a timestamp, and the
record type, as in the following:

    2 3  0.2001 (0.0749)  S>C  Handshake      Certificate

This is record _3_ on connection _2_. The first timestamp
is the time since the beginning of the connection. The second is
the time since the previous record. Both are in seconds.

The next field in the record line is the direction that the record
was going. _C&gt;S_ indicates records transmitted from client to
server and _S&gt;C_ indicates records transmitted from server to client.
_ssldump_ assumes that the host to transmit the first SYN
is the SSL client (this is nearly always correct).

The next field is the record type, one of _Handshake_, _IAlert_,
_ChangeCipherSpec_, or _application\_data_. Finally, _ssldump_
may print record-specific data on the rest of the line. For _Handshake_
records, it prints the handshake message. Thus, this record is
a _Certificate_ message.

_ssldump_ chooses certain record types for further decoding. These
are the ones that have proven to be most useful for debugging:

    ClientHello - version, offered cipher suites, session id
                         if provided)
    ServerHello - version, session_id, chosen cipher suite,
    		     compression method
    Alert - type and level (if obtainable)

Fuller decoding of the various records can be obtained by using the
**-A**
,
**-d**
,
**-k**
and 
**-p**
flags.


<a name="decryption"></a>

# Decryption


_ssldump_ can decrypt traffic between two hosts if the following two
conditions are met:
    1. ssldump has the keys.
    2. Static RSA was used.
In any other case, once encryption starts,
_ssldump_ will only be able to determine the
record type. Consider the following section of a trace.

    1 5  0.4129 (0.1983)  C>S  Handshake      ClientKeyExchange
    1 6  0.4129 (0.0000)  C>S  ChangeCipherSpec
    1 7  0.4129 (0.0000)  C>S  Handshake
    1 8  0.5585 (0.1456)  S>C  ChangeCipherSpec
    1 9  0.6135 (0.0550)  S>C  Handshake
    1 10 2.3121 (1.6986)  C>S  application_data
    1 11 2.5336 (0.2214)  C>S  application_data
    1 12 2.5545 (0.0209)  S>C  application_data
    1 13 2.5592 (0.0046)  S>C  application_data
    1 14 2.5592 (0.0000)  S>C  Alert

Note that the _ClientKeyExchange_ message type is printed
but the rest of the _Handshake_ messages do not have
types. These are the _Finished_ messages, but because they
are encrypted _ssldump_ only knows that they are of type _Handshake_.
Similarly, had the _Alert_ in record 14 happened during the handshake,
it's type and level would have been printed. However, since it
is encrypted we can only tell that it is an alert.


<a name="bugs"></a>

# Bugs


Please send bug reports to https://github.com/adulau/ssldump 

The TCP reassembler is not perfect. No attempt is made to reassemble IP 
fragments and the 3-way handshake and close handshake are imperfectly
implemented. In practice, this turns out not to be much of a problem.

Support is provided for only for Ethernet and loopback interfaces
because that's all that I have. If you have another kind of network
you will need to modify pcap_cb in base/pcap-snoop.c. If you have
direct experience with _ssldump_ on other networks, please send me patches.

_ssldump_ doesn't implement session caching and therefore can't decrypt
resumed sessions.


<a name="see-also"></a>

# See Also


**tcpdump**(1)


<a name="author"></a>

# Author


_ssldump_ was originally written by Eric Rescorla &lt;[ekr@rtfm.com](mailto:ekr@rtfm.com)&gt;. Maintained by a bunch of volunteers, see https://github.com/adulau/ssldump/blob/master/CREDITS - Copyright (C) 2015-2023 the aforementioned volunteers
