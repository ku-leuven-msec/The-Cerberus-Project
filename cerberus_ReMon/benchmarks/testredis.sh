#!/bin/bash

for i in `seq 1 10`
do
    ./redis-native/bin/redis-benchmark --tls --cert /home/dreamer/Cerberus/cerberus_ReMon/benchmarks/conf/redis-tls/redis.crt --key /home/dreamer/Cerberus/cerberus_ReMon/benchmarks/conf/redis-tls/redis.key --cacert /home/dreamer/Cerberus/cerberus_ReMon/benchmarks/conf/redis-tls/ca.crt -h 127.0.0.1 -q
    # command to process dump
    # cat redisexampledump | grep "requests per second" | cut -d':' -f2 | cut -d' ' -f2 | tr -d ' ' | paste -s -d+ | bc | awk -v OFMT='%f' '{print $1/10}'
done
