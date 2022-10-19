#!/usr/bin/env bash

rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/lighttpd.conf.1
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/lighttpd.conf.3
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/lighttpd.conf.5
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/lighttpd_no_security_module.conf.1

rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/redis.conf
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/redis_enable_threading.conf
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/redis_enable_threading_no_tls.conf
rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/conf/redis_no_tls.conf

rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/src/openssl/erimized-shared/Configurations/10-main.conf

rpl -q "/path/to/cerberus_ReMon" "`pwd`" benchmarks/README.md
