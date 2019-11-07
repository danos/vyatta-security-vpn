#!/bin/sh
## Script called up strongswan to bring the vti interface up/down based on the state of the IPsec tunnel.
## Called as vti_up_down vti_intf_name
#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2017, Brocade Communications Systems, Inc.
# All Rights Reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
#
# **** End License ****

# SPDX-License-Identifier: GPL-2.0-only

source /etc/default/vyatta
source /etc/default/locale

# comment to disable logging VPN connections to syslog
VPN_LOGGING=0
#
# tag put in front of each log entry:
TAG=$(basename $0)
#
# syslog facility and priority used:
FAC_PRIO=local0.info

# source shared updown helper code
source /usr/lib/ipsec/vyatta-updown-helper.sh

# only handle v6 events if dataplane supports them
if [ "$PLUTO_VERB" == "up-client-v6" ] || \
    [ "$PLUTO_VERB" == "down-client-v6" ] ; then
    if [ ! -f /opt/vyatta/etc/features/vyatta-security-vpn-ipsec-v1/enable-dataplane-ipsec6 ] ; then
	exit 0
    fi
fi

case "$PLUTO_VERB" in
    route-client)
	/opt/vyatta/sbin/vyatta-vti-config.pl --updown --intf=$1 --action=up
	;;
    up-client|up-client-v6)
	#
	# there might be duplicate CHILD_SAs (via one or more IKE_SAs) for the
	# same connection so don't continue if the interface isn't down
        if ! updown $PLUTO_CONNECTION up ; then
            exit 0
        fi

        #
        # log IPsec client connection setup
        if [ $VPN_LOGGING ] ; then
	    logger -t $TAG -p $FAC_PRIO -- \
		   "+ $PLUTO_PEER_ID $PLUTO_PEER_CLIENT == $PLUTO_PEER -- $PLUTO_ME == $PLUTO_MY_CLIENT"
        fi

	/opt/vyatta/sbin/vyatta-vti-config.pl --updown --intf=$1 --action=up
	;;
    down-client|down-client-v6)
	#
	# there might be duplicate CHILD_SAs (via one or more IKE_SAs) for the
	# same connection so don't down the interface when the first is deleted
	if ! updown $PLUTO_CONNECTION down ; then
	    exit 0
	fi

        #
        # log IPsec client connection teardown
        if [ $VPN_LOGGING ] ; then
            logger -t $TAG -p $FAC_PRIO -- \
		   "- $PLUTO_PEER_ID $PLUTO_PEER_CLIENT == $PLUTO_PEER -- $PLUTO_ME == $PLUTO_MY_CLIENT"
        fi

	/opt/vyatta/sbin/vyatta-vti-config.pl --updown --intf=$1 --action=down
	;;
    *)
	;;
esac

exit 0
