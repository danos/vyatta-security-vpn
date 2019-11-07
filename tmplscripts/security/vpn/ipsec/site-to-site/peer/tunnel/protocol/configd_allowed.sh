#!/bin/sh
protos=$(cat /etc/protocols | awk 'NF && !/^#/ { print $1 }')
protos="all $protos"
echo -n $protos
