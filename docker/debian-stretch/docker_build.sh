#!/bin/bash

ssldump_version=1.4b
distribution=debian-stretch

docker build -t "ssldump-${distribution}:${ssldump_version}" .
