#! /bin/sh

# Copyright (c) 2018-2019 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2014-2017 Brocade Communications Systems, Inc.
# All rights reserved.


# SPDX-License-Identifier: GPL-2.0-only

export IPSEC_CONFS=/etc
export IPSEC_CONFDDIR=/etc/ipsec.d

#
#Set of IPsec commands first
#

#version
echo "IPsec version"
ipsec --version

#directory
echo "IPsec working directory"
ipsec --directory

#statusall
echo "IPsec status"
ipsec statusall

#listall
echo "Info about all certificates/groups/plugins"
ipsec listall

#
#Set of system procedures for showing debug info
#

#pfkey
if [ -r /proc/net/pfkey ];
then
        cat /proc/net/pfkey
        ip -s xfrm state
        ip -s xfrm policy
fi

#ipsec proc
if [ -d /proc/sys/net/ipsec ];
then
        ( cd /proc/sys/net/ipsec && grep '^' * )
fi

#routing ruleset and ip route
echo routing rule set
ip rule list
echo
/opt/vyatta/bin/vtyshow.pl show ip route
echo

#ls -l ipsec
if [ -f /proc/net/ipsec_version ];
then
        ls -l /proc/net/ipsec_*
fi

#ipsec conf
if [ -r /usr/lib/ipsec/_keycensor ];
then
        /usr/lib/ipsec/_include $IPSEC_CONFS/ipsec.conf | /usr/lib/ipsec/_keycensor
fi

if [ -r /usr/lib/ipsec/_secretcensor ];
#ipsec/secrets
then
        /usr/lib/ipsec/_include $IPSEC_CONFS/ipsec.secrets | /usr/lib/ipsec/_secretcensor
fi

#ipsec policies
if [ -n ${IPSEC_CONFDDIR}/policies ];
then
if [ `ls ${IPSEC_CONFDDIR}/policies 2> /dev/null | wc -l` -ne 0 ];
	then
	for policy in ${IPSEC_CONFDDIR}/policies/*
		do
			echo $(basename $policy)
			cat $policy
		done
	fi
fi

#ipsec_version
if [ -r /proc/net/ipsec_version ];
then
        cat /proc/net/ipsec_version
else
        if [ -r /proc/net/pfkey ];
        then
                echo "NETKEY (`uname -r`) support detected"
        else
                echo "no KLIPS or NETKEY support detected"
        fi
fi

#dump database deatils
if [ ! -f '/opt/vyatta/etc/features/vyatta-security-vpn-ipsec-v1/disable-dataplane-ipsec' ]; then
	/opt/vyatta/bin/vplsh -l -c 'ipsec'
fi

# dump current logging options
cat /etc/strongswan.d/charon-logging.conf 2> /dev/null

# dump vyatta-ike-sa-daemon details
echo "# vyatta-ike-sa-daemon state:"
dbus-send --print-reply --type=method_call --system      \
              --dest='net.vyatta.eng.security.vpn.ipsec' \
             '/net/vyatta/eng/security/vpn/ipsec'        \
             'net.vyatta.eng.security.vpn.ipsec.show_debug' 2> /dev/null

hostname
date
