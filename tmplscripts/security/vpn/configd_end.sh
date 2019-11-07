#!/bin/bash
#
# Copyright (c) 2017-2019 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2014, 2016 Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

set -e

/opt/vyatta/sbin/vyatta-security-vpn-secrets

/opt/vyatta/sbin/vyatta-vti-config.pl
/opt/vyatta/sbin/vfp-config.pl

if [ -x /opt/vyatta/sbin/dmvpn-config.pl ]; then
  /opt/vyatta/sbin/dmvpn-config.pl --force_generate_config \
      --config_file='/etc/dmvpn.conf' \
      --secrets_file='/etc/dmvpn.secrets'
fi

/opt/vyatta/sbin/vpn-config.pl \
    --config_file='/etc/ipsec.conf' \
    --secrets_file='/etc/ipsec.secrets'

/opt/vyatta/sbin/vpn-config-global-ike
/opt/vyatta/sbin/vpn-config-vici

if [ -x /opt/vyatta/sbin/vyatta-update-l2tp.pl ]; then
  /opt/vyatta/sbin/vyatta-update-l2tp.pl
fi

# Don't fail if the ipsec command fails.  It is valid for ipsec to exit with nozero status if ipsec is not running.
ipsec rereadall >&/dev/null || true
