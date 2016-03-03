#!/usr/bin/env bash

# used in travis to:
#  - build libsodium
#  - clone sodiumoxide and make cargo use git versionQ

# TODO: move this script somewhere else?

git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/1.0.8
./autogen.sh
./configure --prefix=$HOME/installed_libsodium && \
    make -j$(nproc) && \
    make install
cd ..


git clone https://github.com/dnaq/sodiumoxide
mkdir .cargo
echo 'paths = ["sodiumoxide/libsodium-sys"]' >> .cargo/config
