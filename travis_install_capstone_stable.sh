#!/bin/sh

set -ex
mkdir -p $HOME/src && cd $HOME/src
git clone --depth=50 --branch=3.0.4 https://github.com/aquynh/capstone.git && cd capstone
echo `git log | head`
PREFIX=$HOME/capstone make && PREFIX=$HOME/capstone make install
cd $TRAVIS_BUILD_DIR