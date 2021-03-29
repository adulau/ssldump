#!/bin/bash

ssldump_version=1.4b
distribution=debian-stretch

docker run -it ssldump-${distribution}:${ssldump_version}

