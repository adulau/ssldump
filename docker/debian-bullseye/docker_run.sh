#!/bin/bash

ssldump_version=1.4b
distribution=debian-bullseye

docker run -it ssldump-${distribution}:${ssldump_version}

