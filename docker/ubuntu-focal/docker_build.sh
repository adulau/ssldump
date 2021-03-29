#!/bin/bash

ssldump_version=1.4b
distribution=ubuntu-focal

docker build -t "ssldump-${distribution}:${ssldump_version}" .
