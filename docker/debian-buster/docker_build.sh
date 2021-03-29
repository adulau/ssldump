#!/bin/bash

ssldump_version=1.4b
distribution=debian-buster

docker build -t "ssldump-${distribution}:${ssldump_version}" .
