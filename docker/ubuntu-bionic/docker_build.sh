#!/bin/bash

ssldump_version=1.4b
distribution=ubuntu-bionic

docker build -t "ssldump-${distribution}:${ssldump_version}" .
