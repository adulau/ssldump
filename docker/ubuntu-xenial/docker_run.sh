#!/bin/bash

ssldump_version=1.4b
distribution=ubuntu-xenial

docker run -it ssldump-${distribution}:${ssldump_version}

