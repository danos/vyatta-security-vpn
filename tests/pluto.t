#!/usr/bin/perl -w

# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use File::Basename;
use Cwd 'abs_path';
use lib abs_path(dirname(__FILE__) . '/../lib');

use Test::More 'no_plan';
use Test::MockObject;

my $mock = Test::MockObject->new();
$mock->fake_module('Vyatta::Config');
$mock->fake_module('Vyatta::Configd');
$mock->fake_module('NetAddr::IP');

use_ok('Vyatta::VPN::Pluto', qw( :ALL ) );

use lib dirname(__FILE__);
use TestData_OPMode;

use Test::Vyatta::MockSimple qw(mock_capture_retval);

###

=item slice_hash()

This is a helper to simplify the slicing of a hash. Use it together with
is_deeply() to limit the hash elements to check.

=cut

###

sub slice_hash {
  my ( $hash_ref, @keys ) = @_;
  my %new_hash;
  @new_hash{ sort @keys } = @{ $hash_ref }{ sort @keys };
  return wantarray ? %new_hash : \%new_hash;
}

my %numbrs = ( 1 => '1', 2 => 'test', 3 => '3' );
my %res_numbrs = slice_hash(\%numbrs, qw( 2 ));
is_deeply(\%res_numbrs, { 2 => 'test' }, 'slice_hash hash');
is_deeply(scalar slice_hash(\%numbrs, qw( 2 )), { 2 => 'test' },
          'slice_hash hashref');

is_deeply(\@{[ _make_peer_connection_matcher()->(
    $pluto_ipsec_statusall_down_down[13]) ]},
          [ q(peer-192.168.0.2-tunnel-1),
            { '_tunnelnum' => '1', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');

is_deeply(\@{[ _make_peer_connection_matcher()->($pluto_ipsec_statusall_matcher_test[0]) ]},
          [ q(peer-192.168.0.2-tunnel-1),
            { '_tunnelnum' => '1', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');
is_deeply(\@{[ _make_peer_connection_matcher()->($pluto_ipsec_statusall_matcher_test[1]) ]},
          [ q(peer-192.168.0.2-tunnel-1[2]),
            { '_tunnelnum' => '1[2]', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');
is_deeply(\@{[ _make_peer_connection_matcher()->($pluto_ipsec_statusall_matcher_test[2]) ]},
          [ q(peer-192.168.0.2-tunnel-1[4]),
            { '_tunnelnum' => '1[4]', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');
is_deeply(\@{[ _make_peer_connection_matcher()->($pluto_ipsec_statusall_matcher_test[3]) ]},
          [ q(peer-192.168.0.2-tunnel-1[2]),
            { '_tunnelnum' => '1[2]', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');
is_deeply(\@{[ _make_peer_connection_matcher()->($pluto_ipsec_statusall_matcher_test[4]) ]},
          [ q(peer-192.168.0.2-tunnel-1[4]),
            { '_tunnelnum' => '1[4]', '_peerid' => '192.168.0.2' } ],
          'peer connection matcher');

mock_capture_retval('ipsec statusall', []);
my %th = get_tunnel_info();
is(keys %th, 0, 'gti: empty hash');

%th = get_tunnel_info_peer('192.168.0.2');
is(keys %th, 0, 'gtip: empty hash');

mock_capture_retval('ipsec statusall', \@pluto_ipsec_statusall_down_down);
my %expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_ikelife' => '3600',
    '_ikestate' => 'down',
    '_lid' => '@moon.strongswan.org',
    '_lifetime' => '1200',
    '_lip' => '192.168.0.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '10.1.0.0/16',
    '_natt' => 0,
    '_newestike' => '#0',
    '_newestspi' => '#0',
    '_peerid' => '192.168.0.2',
    '_rid' => '@sun.strongswan.org',
    '_rip' => '192.168.0.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '10.2.0.0/16',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(keys %th, qw( peer-192.168.0.2-tunnel-1 ),
          'gti_pluto: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.0.2-tunnel-1'},
                            keys %expected_th),
          \%expected_th, 'down_down');

%th = get_tunnel_info_peer('192.168.0.2');
is_deeply(keys %th, qw( peer-192.168.0.2-tunnel-1 ),
          'gtip_pluto: returns one tunnel');

mock_capture_retval('ipsec statusall', \@pluto_ipsec_statusall_init_down);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_ikelife' => '28800',
    '_ikestate' => 'init',
    '_lid' => '192.168.100.6',
    '_lifetime' => '3600',
    '_lip' => '192.168.100.6',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '192.168.40.0/24',
    '_natt' => 0,
    '_newestike' => '#0',
    '_newestspi' => '#0',
    '_peerid' => '192.168.100.7',
    '_rid' => '192.168.100.7',
    '_rip' => '192.168.100.7',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '192.168.248.0/24',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(keys %th, qw( peer-192.168.100.7-tunnel-1 ),
          'gti_pluto: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.100.7-tunnel-1'},
                            keys %expected_th),
          \%expected_th, 'init_down');

%th = get_tunnel_info_peer('192.168.100.7');
is_deeply(keys %th, qw( peer-192.168.100.7-tunnel-1 ),
          'gti_pluto: returns one tunnel');

mock_capture_retval('ipsec statusall', \@pluto_ipsec_statusall_up_down);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeexpire' => 3315,
    '_ikehash' => 'HMAC_SHA1',
    '_ikelife' => 28800,
    '_ikestate' => 'up',
    '_lid' => '192.168.100.129',
    '_lifetime' => '3600',
    '_lip' => '192.168.100.129',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '192.168.102.0/24',
    '_natt' => 0,
    '_newestike' => '#3',
    '_newestspi' => '#0',
    '_peerid' => '192.168.100.128',
    '_rid' => '192.168.100.128',
    '_rip' => '192.168.100.128',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '192.168.101.0/24',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(keys %th, qw( peer-192.168.100.128-tunnel-1 ),
          'gtip_pluto: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.100.128-tunnel-1'},
                            keys %expected_th),
          \%expected_th, 'up_down');

%th = get_tunnel_info_peer('192.168.100.128');
is_deeply(keys %th, qw( peer-192.168.100.128-tunnel-1 ),
          'gtip_pluto: returns one tunnel');

mock_capture_retval('ipsec statusall', \@pluto_ipsec_statusall_up_up);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
    '_encryption' => 'AES_CBC_256',
    '_expire' => 2785,
    '_hash' => 'HMAC_SHA1',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeexpire' => 3198,
    '_ikehash' => 'HMAC_SHA1',
    '_ikelife' => 28800,
    '_ikestate' => 'up',
    '_inbytes' => '0',
    '_inspi' => 'c5e524d9',
    '_lid' => '192.168.100.129',
    '_lifetime' => '3600',
    '_lip' => '192.168.100.129',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '192.168.102.0/24',
    '_natt' => 0,
    '_newestike' => '#3',
    '_newestspi' => '#4',
    '_outbytes' => '0',
    '_outspi' => 'c61fd7e2',
    '_peerid' => '192.168.100.128',
    '_pfsgrp' => '<N/A>',
    '_rid' => '192.168.100.128',
    '_rip' => '192.168.100.128',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '192.168.101.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(keys %th, qw( peer-192.168.100.128-tunnel-1 ),
          'gti_pluto: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.100.128-tunnel-1'},
                            keys %expected_th),
          \%expected_th, 'up_up');

%th = get_tunnel_info_peer('192.168.100.128');
is_deeply(keys %th, qw( peer-192.168.100.128-tunnel-1 ),
          'gti_pluto: returns one tunnel');

