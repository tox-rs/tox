#!/bin/bash

# used in travis to:
#  - pull in dependencies for building libsodium
#  - build required libsodium
#  - clone sodiumoxide and make cargo use git version

sudo apt-get update -qq
sudo apt-get install -y build-essential libtool autotools-dev automake checkinstall check git yasm pkg-config
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/1.0.8
./autogen.sh
./configure && make -j$(nproc)
sudo checkinstall --install --pkgname libsodium --pkgversion 1.0.8 --nodoc -y
sudo ldconfig
cd ..
