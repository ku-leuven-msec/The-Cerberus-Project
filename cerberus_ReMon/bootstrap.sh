#!/bin/bash
set -e

ORIG_PWD=$(pwd)

mkdir -p deps

# Install the necessary ubuntu packages
if [ -e /usr/bin/apt ]
then
    sudo apt install clang build-essential git libtool libunwind-dev libbsd-dev nasm libboost-all-dev ruby gcc g++ libselinux1-dev musl-tools libelf-dev libdwarf-dev libgmp-dev libmpfr-dev libmpc-dev libconfig-dev libcap-dev cmake bison flex git texinfo texi2html zlib1g-dev libunwind8 liblzma5 liblzma-dev automake e2fslibs-dev rpl
fi

# Fix paths
build_scripts/correct_paths.sh

# Download & Build libjson
if [ ! -e deps/jsoncpp ]
then
    git clone https://github.com/open-source-parsers/jsoncpp.git deps/jsoncpp
    cd deps/jsoncpp
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_CXX_FLAGS=-O3 ..
    make -j `getconf _NPROCESSORS_ONLN`
    cd ../../../
fi

# Download & Build musl
if [ ! -e deps/musl ]
then
    wget http://www.musl-libc.org/releases/musl-1.1.19.tar.gz
    tar xzf musl-1.1.19.tar.gz
    mv musl-1.1.19 deps/musl
    #	git clone git://git.musl-libc.org/musl deps/musl
    cd deps/musl
    ./configure --prefix=$ORIG_PWD/deps/musl-install --exec-prefix=$ORIG_PWD/deps/musl-install
    make -j `getconf _NPROCESSORS_ONLN`
    make install
    cd ../../
fi

# All done!
printf "\033[0;32mCerberus's dependencies are now installed!\033[0m\n"

