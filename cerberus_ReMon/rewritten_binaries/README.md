# Rewritten executables and how to rewrite/run them

## Rewrite XRSTOR (0FAE29) instruction in nginx-1.19.10
1) Rewrite with: `LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so ../../../bin/binaryanalysis/ba_erim nginx 0FAE29 1 FULL > nginx.ea`
2) Copy nginx.erim to nginx's sbin directory (nexto to "regular" nginx executable)
3) Run using: `./MVEE -N 1 -- "LD_LIBRARY_PATH=/path_to/libs /path/to/nginx.erim"`

## Failed to rewrite XRSTOR (0FAE6C) instruction in redis-6.2.2

## Failed to rewrite XRSTOR (0FAE6C) instructions in libm.so

## Failed to rewrite XRSTOR (0FAE2F, 0FAE28) instructions in libc.so