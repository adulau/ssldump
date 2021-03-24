#!/bin/bash

ssldump_version=1.4b
distribution=ubuntu-groovy

docker run -it ssldump-${distribution}:${ssldump_version}

