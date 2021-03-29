#!/bin/bash

ssldump_version=1.4b
distribution=debian-buster

docker run -it ssldump-${distribution}:${ssldump_version}

