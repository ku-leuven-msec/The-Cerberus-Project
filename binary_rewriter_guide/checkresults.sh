#!/bin/bash

# ./checkresults.sh inadxrstor.ea
# Check result failed for inadxrstor.ea

# ./checkresults.sh inadxrstor.erim.ea
# inadxrstor.erim.ea: Successful

sucRw=`grep 'numWRPKRU>0' $1 | wc -l`

if [ "$sucRw" != "1" ]
then
    echo "Check result failed for $1"
    exit 1;
else
    echo "$1: Successful"
fi
