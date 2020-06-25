#
# This helper library is meant to be sourced by strongswan updown scripts.
#
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2016, Brocade Communications Systems, Inc.
# All Rights Reserved.
#

# SPDX-License-Identifier: GPL-2.0-only

updown () {
    local CONN=$1
    local OP=$2
    local DIR=/run/$(basename $0)
    local RES=-1

    mkdir -p ${DIR}
    exec 3>${DIR}/${CONN}.lock
    flock --exclusive 3
    COUNT=$(cat ${DIR}/${CONN} 2>/dev/null)
    if [ "${OP}" = "up" ] ; then
	RES=${COUNT:-0}
	COUNT=$((COUNT+1))
    elif [ "${OP}" = "down" ] ; then
	[ 0${COUNT} -gt 0 ] && COUNT=$((COUNT-1))
	RES=${COUNT}
    fi
    echo ${COUNT} > ${DIR}/${CONN}
    exec 3>&-
    return $RES
}
