## The following instructions have been tested on Debian 8 (We didn't port the binary rewriter to Ubuntu 18.04)

## Clone ERIM repo
```
git clone https://github.com/vahldiek/erim
```

## Dependencies
```
sudo apt-get install build-essential libboost-all-dev
```

## Building the binary rewriter
```
cd path/to/erim/src/binaryanalysis/
make
```

## Examples
```
cd test/
# replace checkresults.sh with "our" checkresults.sh (Cerberus/binary_rewriter_guide/checkresults.sh)

# we can do this in an Ubuntu 18.04 machine and move the binary inside the Debian 8 VM/Docker
gcc inadxrstor.c -o inadxrstor

# simplest way to create the analysis file (.ea)
LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so ../../../bin/binaryanalysis/ba_erim inadxrstor 0F01EF 1 location > inadxrstor.ea

# check the analysis file (.ea) to see if there are dangerous wpkru instructions
./checkresults.sh inadxrstor.ea
this should return failure

# create a more detailed analysis file (.ea)
LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so ../../../bin/binaryanalysis/ba_erim inadxrstor 0F01EF 1 analysis > inadxrstor.ea

# create the analysis file (.ea) and also the new rewritten binary (inadxrstor3.erim)
LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so ../../../bin/binaryanalysis/ba_erim inadxrstor 0F01EF 1 full > inadxrstor.ea

# create the analysis file of the rewritten binary and check it for dangerous wpkru instructions
LD_LIBRARY_PATH=../libs DYNINSTAPI_RT_LIB=../libs/libdyninstAPI_RT.so ../../../bin/binaryanalysis/ba_erim inadxrstor.erim 0F01EF 1 analysis > inadxrstor.erim.ea
./checkresults.sh inadxrstor.erim.ea
this should return success

# run the new rewritten binary (Note that some binaries of the test folder are not runnable files)
LD_LIBRARY_PATH=../libs/ ./inadxrstor.erim
```
