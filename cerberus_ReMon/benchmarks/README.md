# Client/Server configuration we used for our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf)

```
sudo systemctl stap NetworkManager.service
sudo systemctl stop NetworkManager.service # this is needed for the server to not reset the connection
sudo ifconfig enp109s0 10.0.0.20 netmask 255.255.255.0 up # client
sudo ifconfig enp109s0 10.0.0.10 netmask 255.255.255.0 up # server
# Then you have to update the corresponding server config files to use the above addresses (by default the config files use localhost)
# NOTE that placing the benchmarking client on the same machine as the server significantly affects the performance evaluation (normally benchmarking client is placed on a different machine)
```

# Build benchmarks
Just run `./build.sh`

# CPI nginx
```
vim /path/to/cerberus_ReMon/benchmarks/src/erim-cpi/erim/bench/speccpu/scripts/config.sh
# change USER to your user

# Now go check what kind of linker is installed on your system. You need to
# make sure to link your programs with ld.gold; Ubuntu by default uses ld.bfd.
# So either update your Makefiles to link with ld.gold or replace ld.bfd with
# ld.gold:

cd /usr/bin
ls -lsah ld
# ensure that it is linked as follows: ld -> ld.bfd
# ensure that ld.gold exists:
ls -lsah ld.gold
sudo rm ld
sudo ln -s ld.gold ld

# Native execution (different compiler version though ... to fix need to compile with the CPI compiler but without the -fcpi, -fcps options)
/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1

# ERIM-CPI (no sandbox)
/path/to/cerberus_ReMon/benchmarks/nginx-erim-cpi/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1

vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ERIM_INTEGRITY_ONLY, ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
cd /path/to/cerberus_ReMon/MVEE/bin/Release
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erim-cpi/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1"

# Restore ld
cd /usr/bin
sudo rm ld
sudo ln -s x86_64-linux-gnu-ld ld  
```

# SS nginx, lighttpd

```
sudo apt-get install libgtest-dev
# Note that this package only install source files. You have to compile the code yourself to create the necessary library files.
# These source files should be located at /usr/src/gtest. Browse to this folder and use cmake to compile the library.
sudo apt-get install cmake # install cmake
cd /usr/src/gtest
sudo cmake CMakeLists.txt
sudo make
 
# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.a /usr/lib

# Native execution (different compiler version though ... to fix need to compile with the SS compiler but without the shadow stack protection)
/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1

# ERIM-SS (no sandbox)
/path/to/cerberus_ReMon/benchmarks/nginx-erim-ss/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1

vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ERIM_INTEGRITY_ONLY, ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
cd /path/to/cerberus_ReMon/MVEE/bin/Release
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erim-ss/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx_no_security_module.conf.1"

# Native execution (different compiler version though ... to fix)
/path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd_no_security_module.conf.1

# ERIM-SS (no sandbox)
/path/to/cerberus_ReMon/benchmarks/lighttpd-erim-ss/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd_no_security_module.conf.1

vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ERIM_INTEGRITY_ONLY, ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
cd /path/to/cerberus_ReMon/MVEE/bin/Release
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-erim-ss/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd_no_security_module.conf.1"
```

# ERIM/XOM-Switch nginx (https)
## Running native nginx (choose one of the conf* files)
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.1
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.3
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.5
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.10
```

## Running nginx with erimized openssl (choose one of the conf* files)
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.1
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.3
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.5
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.10
```

## Running nginx with erimized openssl and Cerberus (choose one of the conf* files)
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.1"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.3"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.5"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-erimized/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.10"
```

## Running nginx with Intel XOM-Switch (choose one of the conf* files)
```
sudo cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-original.so /lib64/ld-xom.so
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.1
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.3
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.5
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.10
```

## Running nginx with Intel XOM-Switch and Cerberus (choose one of the conf* files)
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_XOM_SWITCH_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
# Copy XOM-patched ld.so to the patched binaries and backup the original patched ld.so
cp /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so .
cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-cerberus.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.1"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.3"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.5"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/nginx-native/sbin/nginx -c /path/to/cerberus_ReMon/benchmarks/conf/nginx.conf.10"
# Restore backed up ld.so
cp ld.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
```

## Benchmarking nginx
```
cd /path/to/cerberus_ReMon/benchmarks
wrk/wrk -t1 -c10 -d10s --timeout 10s http://127.0.0.1:3000/index.html  
wrk/wrk -t1 -c10 -d10s --timeout 10s https://127.0.0.1:3333/index.html
```

# ERIM/XOM-Switch lighttpd (https)
# https://redmine.lighttpd.net/projects/1/wiki/Server_max-workerDetails#Limitations -- server.max-worker = 0 is strongly recommended, often using the least resources and being the most performant, except in specific uses cases.
## Running native lighttpd
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5
```

## Running lighttpd with erimized openssl
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5
```

## Running lighttpd with erimized openssl and Cerberus
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-erimized/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5"
```

## Running lighttpd with Intel XOM-Switch (choose one of the conf* files)
```
sudo cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-original.so /lib64/ld-xom.so
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5
```

## Running lighttpd with Intel XOM-Switch and Cerberus (choose one of the conf* files)
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_XOM_SWITCH_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
# Copy XOM-patched ld.so to the patched binaries and backup the original patched ld.so
cp /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so .
cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-cerberus.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path/to/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5"
# Restore backed up ld.so
cp ld.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
```

## Benchmarking lighttpd
```
cd /path/to/cerberus_ReMon/benchmarks
wrk/wrk -t1 -c10 -d10s --timeout 10s http://127.0.0.1:3000/index.html  
wrk/wrk -t1 -c10 -d10s --timeout 10s https://127.0.0.1:3333/index.html
```

# ERIM/XOM-Switch redis (tls)
## Running native redis (choose one of the conf* files)
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis.conf
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading.conf
```

## Running redis with erimized openssl (choose one of the conf* files)
```
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/redis-erimized/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis.conf
LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/erimized-shared/.openssl/lib/:/usr/local/lib" /path/to/cerberus_ReMon/benchmarks/redis-erimized/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading.conf
```

## Running redis with erimized openssl and Cerberus (choose one of the conf* files)
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_ERIM_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-erimized/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis.conf"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-erimized/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading.conf"
```

## Running redis with Intel XOM-Switch (choose one of the conf* files)
```
sudo cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-original.so /lib64/ld-xom.so
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis.conf
LD_PRELOAD="/path/to/cerberus_ReMon/xom_switch_libs/libc-xom-original.so" LD_LIBRARY_PATH="/path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /lib64/ld-xom.so /path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading.conf
```

## Running redis with Intel XOM-Switch and Cerberus (choose one of the conf* files)
```
vim /path/to/cerberus_ReMon//MVEE/Inc/MVEE_build_config.h
# Cerberus execution ... enable ENABLE_XOM_SWITCH_POLICY through MVEE_build_config.h and recompile
cd /path/to/cerberus_ReMon
make -j 4
mkdir -p /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cp /path/to/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/*.so.1.1 /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
cd /path/to/cerberus_ReMon/patched_binaries/openssl/amd64
ln -f -s libssl.so.1.1 libssl.so
ln -f -s libcrypto.so.1.1 libcrypto.so
cd /path/to/cerberus_ReMon/MVEE/bin/Release
# Copy XOM-patched ld.so to the patched binaries and backup the original patched ld.so
cp /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so .
cp /path/to/cerberus_ReMon/xom_switch_libs/ld-xom-cerberus.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
vim MVEE.ini
# Set "use_custom_openssl" : true,
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis.conf"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_no_tls.conf"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading.conf"
./MVEE -N 1 -- "/path/to/cerberus_ReMon/benchmarks/redis-native/bin/redis-server /path/to/cerberus_ReMon/benchmarks/conf/redis_enable_threading_no_tls.conf"
# Restore backed up ld.so
cp ld.so /path/to/cerberus_ReMon/patched_binaries/libc/amd64/2.27/ld.so
```

## Benchmarking redis
```
cd /path/to/cerberus_ReMon/benchmarks/redis-native/bin
./redis-benchmark --tls \
    --cert /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/redis.crt \
    --key /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/redis.key \
    --cacert /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/ca.crt -h 127.0.0.1 -q
./redis-benchmark --threads 3 \
    --tls \
    --cert /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/redis.crt \
    --key /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/redis.key \
    --cacert /path/to/cerberus_ReMon/benchmarks/conf/redis-tls/ca.crt -h 127.0.0.1 -q
./redis-benchmark -h 127.0.0.1 -q
./redis-benchmark --threads 3 -h 127.0.0.1 -q 
```