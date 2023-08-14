#!/bin/bash

ssldump_version=$(awk '/\s+VERSION/ {print $2}' ../../CMakeLists.txt)
distribution=$(awk '/^FROM/ {gsub(":","-"); print $2}' Dockerfile)

docker build -t "ssldump-${distribution}:${ssldump_version}" .
