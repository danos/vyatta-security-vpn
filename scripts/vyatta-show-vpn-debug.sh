#!/bin/bash

# Copyright (c) 2018-2020, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2014-2017 Brocade Communications Systems, Inc.
# All rights reserved.

#
# SPDX-License-Identifier: GPL-2.0-only
#

# Legacy stroke commands.
# Will be removed very soon.
(
echo "IPsec version"
ipsec --version

echo "IPsec working directory"
ipsec --directory

echo "IPsec status"
ipsec statusall

echo "Info about all certificates/groups/plugins"
ipsec listall
)

(

echo "IKE control-plane version"
swanctl --version
echo
swanctl --list-conns
echo
swanctl --list-sas
echo
swanctl --list-pols
echo
echo "Info about all certificates/groups/plugins"
swanctl --stats
echo
swanctl --counters
echo
swanctl --list-authorities
echo
swanctl --list-certs
echo
swanctl --list-pools
echo
swanctl --list-algs

) 2> /dev/null

#pfkey
if [ -r /proc/net/pfkey ];
then
        cat /proc/net/pfkey
        ip -s xfrm state
        ip -s xfrm policy
fi

echo routing rule set
ip rule list
echo
/opt/vyatta/bin/vtyshow.pl show ip route
echo
ip route list table all
echo


#dump dataplane deatils
if [ ! -f '/opt/vyatta/etc/features/vyatta-security-vpn-ipsec-v1/disable-dataplane-ipsec' ]; then
        /opt/vyatta/bin/vplsh -l -c 'ipsec'
        echo
        # query all VRFs
        for n in `ls -1d /sys/class/net/vrf*/`; do
                vrf=$( basename $n )

                echo "# vplsh ipsec commands for VRF $vrf"
                /opt/vyatta/bin/vplsh -l -c "ipsec spd vrf_id $(cat /sys/class/net/$vrf/ifindex)"
                /opt/vyatta/bin/vplsh -l -c "ipsec sad vrf_id $(cat /sys/class/net/$vrf/ifindex)"
                /opt/vyatta/bin/vplsh -l -c "ipsec spi vrf_id $(cat /sys/class/net/$vrf/ifindex)"
                /opt/vyatta/bin/vplsh -l -c "ipsec bind vrf_id $(cat /sys/class/net/$vrf/ifindex)"
                echo
        done
        # punt path is required when dataplane is used for IPsec
        iptables-save
        echo
fi

# dump vyatta-ike-sa-daemon details
echo "# vyatta-ike-sa-daemon state:"
dbus-send --print-reply --type=method_call --system      \
              --dest='net.vyatta.eng.security.vpn.ipsec' \
             '/net/vyatta/eng/security/vpn/ipsec'        \
             'net.vyatta.eng.security.vpn.ipsec.show_debug' 2> /dev/null

hostname
date
