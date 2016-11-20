
# (unofficial repository) of ssldump

SSLDUMP 0.9b3 + a myriad of patches (from Debian and other distributions + contribution (via PR))

ssldump is an SSLv3/TLS network protocol analyzer. It identifies TCP
connections on the chosen network interface and attempts to interpret
them as SSLv3/TLS traffic. When it identifies SSLv3/TLS traffic, it
decodes the records and displays them in a textual form to stdout. If
provided with the appropriate keying material, it will also decrypt
the connections and display the application data traffic.

[original and (old) README](README)

# Why do you maintain this repository?

Because it's a mess. The software maintenance process for old free (unmaintained) software
like ssldump is a complete chaotic process. I do this to ease my pain and this could help
other too (but this is just a collateral damage).

# Where do you use ssldump?

I used it for a relatively small project called Passive SSL. For more information, [Passive SSL Passive Detection and Reconnaissance Techniques, to Find, Track, and Attribute Vulnerable ”Devices”](https://www.first.org/resources/papers/conf2015/first_2015_-_leverett_-_dulaunoy_-_passive_detection_20150604.pdf).
Additional back-end code available is in the [crl-monitor ](https://github.com/adulau/crl-monitor/tree/master/bin/x509) repository.

## Contributing

The contributing policy is simple. If you have a patch to propose, make a pull-request
via the interface. If the patch works for me, it's merged.


