#!/bin/sh

rm -Rf build && cmake -B build -G Ninja && ninja -C build
