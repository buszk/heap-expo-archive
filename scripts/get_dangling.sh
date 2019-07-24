#!/bin/bash

if [[ $# != 1 ]]; then
    echo "$0 log"
    exit
fi

log=$1
grep Dangling ${log}| awk '{print $6 $7 $4 $5}' | sort | uniq | sed 's/\[/ /g'| sed 's/\]/ /g' | sed 's/,//g'
