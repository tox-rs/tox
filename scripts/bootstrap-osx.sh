#!/usr/bin/env bash

# used in travis to:
#  - build libsodium

git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/1.0.8
./autogen.sh
./configure --prefix=$HOME/installed_libsodium && \
    make -j$(nproc) && \
    make install
cd ..
