#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::Constants;

use strict;
use warnings;

use parent qw(Exporter);
our @EXPORT_OK = qw(%TUNNEL_DEFAULTS IPSEC_CONF DMVPN_CONF VFP_STATE_DIR);

our %TUNNEL_DEFAULTS = (
  _peerid     => undef,
  _tunnelnum  => undef,
  _said       => undef,
  _lip        => 'n/a',
  _rip        => 'n/a',
  _lid        => 'n/a',
  _rid        => 'n/a',
  _lsnet      => 'n/a',
  _rsnet      => 'n/a',
  _lproto     => 'all',
  _rproto     => 'all',
  _lport      => 'all',
  _rport      => 'all',
  _lca        => undef,
  _rca        => undef,
  _newestspi  => 'n/a', # aka. CHILD_SA unique id (5.3.0+), used to be reqid.
  _reqid      => 'n/a', # since strongswan 5.3.0 the CHILD_SA reqid
                        # is no longer unique. Due to overlapping CHILD_SA
                        # support.
  _newestike  => 'n/a',
  _encryption => 'n/a',
  _hash       => 'n/a',
  _inspi      => 'n/a',
  _outspi     => 'n/a',
  _pfsgrp     => 'n/a',
  _ikeencrypt => 'n/a',
  _ikehash    => 'n/a',
  _natt       => 'n/a',
  _natsrc     => 'n/a',
  _natdst     => 'n/a',
  _ikestate   => "down",
  _dhgrp      => 'n/a',
  _state      => undef,
  _inbytes    => 'n/a',
  _outbytes   => 'n/a',
  _ikelife    => 'n/a',
  _ikeexpire  => 'n/a',
  _ikeatime   => 'n/a',
  _lifetime   => 'n/a',
  _atime      => 'n/a',
  _ikever     => 'n/a'
);

use constant IPSEC_CONF => "/etc/ipsec.conf";
use constant DMVPN_CONF => "/etc/dmvpn.conf";

use constant VFP_STATE_DIR => '/var/lib/vyatta-security-vpn/vfp/';

1;
