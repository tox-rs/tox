#!/bin/bash

# used in travis to download & install libsodium

wget http://archive.ubuntu.com/ubuntu/pool/universe/libs/libsodium/libsodium18_1.0.13-1_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/universe/libs/libsodium/libsodium-dev_1.0.13-1_amd64.deb

sudo dpkg -i libsodium-dev_1.0.13-1_amd64.deb libsodium18_1.0.13-1_amd64.deb
