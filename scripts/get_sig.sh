#!/bin/bash

if [[ $# != 3 ]]; then
    echo "$0 binary log sig"
    exit
fi
bin=$1
log=$2
sig=$3
grep "SIG\[${sig}" ${log} -A 8|sed 's/\[/ /g' | sed 's/\]//g' |awk '{print $2}'|grep 0x|while read -r line; do addr2line -a $line -e ${bin};done
