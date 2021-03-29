#!/bin/bash

ssldump_version=1.4b
distribution=debian-bullseye

docker build -t "ssldump-${distribution}:${ssldump_version}" .
