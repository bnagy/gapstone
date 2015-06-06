#!/bin/sh

set -ex
mkdir -p $HOME/src && cd $HOME/src
wget https://github.com/aquynh/capstone/archive/3.0.3.tar.gz
tar -zxvf 3.0.3.tar.gz
cd capstone-3.0.3 && ./make.sh && sudo make install
cd $TRAVIS_BUILD_DIR