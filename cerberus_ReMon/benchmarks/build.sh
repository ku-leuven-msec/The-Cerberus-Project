#!/bin/bash

ORIG_PWD=$(pwd)

# Download & Build wrk
if [ ! -e wrk ]
then
	git clone https://github.com/balexios/wrk.git wrk
	cd wrk
	make -j `getconf _NPROCESSORS_ONLN`
	cd ../
fi

#builds nginx with specified openssl verison or build native and erimized

nginxloc=$ORIG_PWD/src/nginx
lighttpdloc=$ORIG_PWD/src/lighttpd
redisloc=$ORIG_PWD/src/redis
opensslloc=$ORIG_PWD/src/openssl
webbench=$ORIG_PWD
speccpu=$ORIG_PWD/src/erim-cpi/erim/bench/speccpu
erimss=$ORIG_PWD/src/erim-ss/

cd ..
cerberus_ReMon_dir=$(pwd)
cd $ORIG_PWD

#$1 openssl folder
build_nginx() {
    basename=`basename $1`

    basename=$basename$ccname	

    echo "building $basename"

    cd $nginxloc

    make clean

    # For some reason the commented compilation instructions produce an executable that fails under Intel XOM-Switch execution
    #./configure "--prefix=$webbench/nginx-$basename/" --with-file-aio --without-http_rewrite_module --with-http_ssl_module "--with-openssl=$1" --with-ld-opt="$2" --with-cc-opt="-I $ORIG_PWD/src/erim/ -D_GNU_SOURCE"#--with-openssl-opt='-d' --with-debug
    ./configure "--prefix=$webbench/nginx-$basename/" --with-file-aio --without-http_rewrite_module --with-http_ssl_module --with-ld-opt="$2" --with-cc-opt="-I $ORIG_PWD/src/erim/ -D_GNU_SOURCE"#--with-openssl-opt='-d' --with-debug

    make -j40 && make install

    cd -
}

build_lighttpd() {
    cd $lighttpdloc

    make clean

    ./autogen.sh
    ./configure "--prefix=$webbench/lighttpd-native/" --without-zlib --without-bzip2 --without-pcre --with-openssl=$webbench/openssl/native-shared/.openssl/ --with-openssl-includes=$webbench/openssl/native-shared/.openssl/include --with-openssl-libs=$webbench/openssl/native-shared/.openssl/lib

    make -j40 && make install

    cd -
}

build_lighttpd_erimized() {
    cd $lighttpdloc

    make clean

    ./autogen.sh
    ./configure "--prefix=$webbench/lighttpd-erimized/" --without-zlib --without-bzip2 --without-pcre --with-openssl=$webbench/openssl/erimized-shared/.openssl/ --with-openssl-includes=$webbench/openssl/erimized-shared/.openssl/include --with-openssl-libs=$webbench/openssl/erimized-shared/.openssl/lib

    make -j40 && make install

    cd -
}

build_redis() {
    cd $redisloc

    make clean

    make MALLOC=libc BUILD_TLS=yes CFLAGS="-I$webbench/openssl/native-shared/.openssl/include" LDFLAGS="-L$webbench/openssl/native-shared/.openssl/lib" -j `getconf _NPROCESSORS_ONLN`
    make PREFIX="$webbench/redis-native/" install

    cd -
}

build_redis_erimized() {
    cd $redisloc

    make clean

    make MALLOC=libc BUILD_TLS=yes CFLAGS="-I$webbench/openssl/erimized-shared/.openssl/include" LDFLAGS="-L$webbench/openssl/erimized-shared/.openssl/lib" -j `getconf _NPROCESSORS_ONLN`
    make PREFIX="$webbench/redis-erimized/" install

    cd -
}

build_openssl() {
    basename=`basename $1`

    basename=$basename$ccname

    echo "building $basename"

    cd $opensslloc/$basename

    make clean

    CFLAGS=-fPIC ./config shared --prefix=$webbench/openssl/$basename/.openssl/

    make -j40 && make install

    cd -
}

build_erim_cpi() {
    cd $speccpu

    sudo ./scripts/init.sh
    scripts/buildLevee.sh

    cd -
}

build_nginx_erim_cpi() {
    cd $nginxloc

    make clean

    ./configure "--prefix=$webbench/nginx-erim-cpi/" --with-cc=$ORIG_PWD/src/erim-cpi/erim/bench/speccpu/leveeERIM/bin/clang --with-cc-opt="-flto -fcpi" --with-ld-opt="-flto -fcpi"

    make -j40 && make install

    cd -
}

build_erim_ss() {
    cd $erimss
    tar -xzf ShadowStack.tar.gz
    cd ShadowStack/Compiler-Impl

    ./configure.sh
    make -j40

    cd -
}

build_nginx_erim_ss() {
    cd $nginxloc

    make clean

    ./configure "--prefix=$webbench/nginx-erim-ss/" --with-cc=$ORIG_PWD/src/erim-ss/ShadowStack/Compiler-Impl/stuff_build/debug-install/bin/clang

    make -j40 && make install

    cd -
}

build_lighttpd_erim_ss() {
    cd $lighttpdloc

    make clean

    ./autogen.sh
    CC=$ORIG_PWD/src/erim-ss/ShadowStack/Compiler-Impl/stuff_build/debug-install/bin/clang ./configure "--prefix=$webbench/lighttpd-erim-ss/"

    make -j40 && make install

    cd -
}

# build common and erim library
make -s -C $ORIG_PWD/src/common
make -s -C $ORIG_PWD/src/erim

build_nginx $ORIG_PWD/src/openssl/native "$ORIG_PWD/bin/erim/liberim.a"
build_nginx $ORIG_PWD/src/openssl/erimized "$ORIG_PWD/bin/erim/liberim.a"

build_openssl $ORIG_PWD/src/openssl/native-shared
build_openssl $ORIG_PWD/src/openssl/erimized-shared

build_lighttpd
build_lighttpd_erimized

build_redis
build_redis_erimized

build_erim_cpi
build_nginx_erim_cpi

build_erim_ss
build_nginx_erim_ss
build_lighttpd_erim_ss