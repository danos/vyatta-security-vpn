#!/bin/bash

# Copyright (c) 2014-2015 Brocade Communications Systems, Inc.
# All rights reserved.

local -a array ;
array=( /var/lib/dhcp/dp* /var/lib/dhcp/br* /var/lib/dhcp/bond* ) ;
echo  -n ${array[@]##*/}
