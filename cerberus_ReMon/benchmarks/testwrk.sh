#!/bin/bash

for i in `seq 1 10`
do
    # wrk/wrk -t1 -c10 -d10s --timeout 10s http://127.0.0.1:3000/index.html
    wrk/wrk -t1 -c10 -d10s --timeout 10s https://127.0.0.1:3333/index.html | grep Requests | cut -d':' -f2 | tr -d ' '
done