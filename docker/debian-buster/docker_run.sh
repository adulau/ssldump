#!/bin/bash

local_if=ens3f0
container_ip=172.17.0.2
ssldump_version=1.4b
distribution=debian-buster

sudo iptables -t mangle -I PREROUTING 1 -i ${local_if} -j TEE --gateway ${container_ip}
sudo iptables -t mangle -I POSTROUTING 1 -o ${local_if} -j TEE --gateway ${container_ip}

docker run -it ssldump-${distribution}:${ssldump_version}

sudo iptables -t mangle -D PREROUTING 1
sudo iptables -t mangle -D POSTROUTING 1

