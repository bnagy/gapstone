#!/bin/sh

set -ex
mkdir -p $HOME/src && cd $HOME/src
git clone https://github.com/aquynh/capstone.git && cd capstone && git checkout next
echo `git log | head`
./make.sh && sudo make install
cd $TRAVIS_BUILD_DIR