#!/usr/bin/perl -w

# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use File::Basename;
use Cwd 'abs_path';
use lib abs_path(dirname(__FILE__) . '/../lib');

use Test::More 'no_plan';
use Test::MockObject;
use Data::Dumper;

my $mock = Test::MockObject->new();
$mock->fake_module('Vyatta::Config');
$mock->fake_module('Vyatta::Configd');
$mock->fake_module('NetAddr::IP');

use_ok('Vyatta::VPN::Charon', qw( :ALL ) );

use lib dirname(__FILE__);
use TestData_OPMode;

use Test::Vyatta::MockSimple qw(mock_capture_retval mock_read_file_retval);

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

mock_read_file_retval('/etc/ipsec.conf', \@ipsec_conf_snippet);

my %numbrs = ( 1 => '1', 2 => 'test', 3 => '3' );
my %res_numbrs = slice_hash(\%numbrs, qw( 2 ));
is_deeply(\%res_numbrs, { 2 => 'test' }, 'slice_hash hash');
is_deeply(scalar slice_hash(\%numbrs, qw( 2 )), { 2 => 'test' },
          'slice_hash hashref');

is_deeply(\@{[ _make_peer_connection_matcher()->($charon_ipsec_statusall_matcher_test[0]) ]},
          [ q(peer-192.168.100.6-tunnel-1),
            { '_tunnelnum' => '1', '_peerid' => '192.168.100.6' } ],
          'peer connection matcher (charon)');
is_deeply(\@{[ _make_peer_connection_matcher()->($charon_ipsec_statusall_matcher_test[1]) ]},
          [ q(peer-192.168.100.6-tunnel-1[1]),
            { '_tunnelnum' => '1', '_peerid' => '192.168.100.6' } ],
          'peer connection matcher (charon)');
is_deeply(\@{[ _make_peer_connection_matcher()->($charon_ipsec_statusall_matcher_test[2]) ]},
          [ q(peer-192.168.100.6-tunnel-1{2}),
            { '_tunnelnum' => '1', '_peerid' => '192.168.100.6' } ],
          'peer connection matcher (charon)');

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_down_down);
my %expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_ikelife' => '28800',
    '_ikeatime' => 'n/a',
    '_ikestate' => 'down',
    '_ikever' => '1',
    '_lid' => '192.168.100.7',
    '_lip' => '192.168.100.7',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '192.168.248.0/24',
    '_natt' => 'n/a',
    '_reqid' => 'n/a',
    '_peerid' => '192.168.100.6',
    '_rid' => '192.168.100.6',
    '_rip' => '192.168.100.6',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '192.168.40.0/24',
    '_tunnelnum' => '1',
    '_said'      => undef
);

my %th = get_tunnel_info();
is_deeply(join(' ', keys %th), qw( peer-192.168.100.6-tunnel-1 ),
          'gti_charon: returns one tunnel');
is_deeply($th{'peer-192.168.100.6-tunnel-1'}, \%expected_th,
          'charon_down_down: %th matches');

%th = get_tunnel_info_peer('192.168.100.6');
is_deeply(join(' ', keys %th), qw( peer-192.168.100.6-tunnel-1 ),
          'gtip_charon: returns one tunnel');

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_init_down);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_ikelife' => '28800',
    '_ikeatime' => 'n/a',
    '_ikestate' => 'init',
    '_ikever' => '1',
    '_lid' => 'any',
    '_lip' => '192.168.100.7',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_natt' => 'n/a',
    '_peerid' => '192.168.100.6',
    '_rid' => 'any',
    '_rip' => '192.168.100.6',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_tunnelnum' => '1',
    '_said'      => undef
);

%th = get_tunnel_info();
is_deeply(join(' ', keys %th), qw( peer-192.168.100.6-tunnel-1[1] ),
          'gti_charon: returns one tunnel');
is_deeply($th{'peer-192.168.100.6-tunnel-1[1]'}, \%expected_th,
          'charon_init_down: %th matches');

%th = get_tunnel_info_peer('192.168.100.6');
is_deeply(join(' ', keys %th), qw( peer-192.168.100.6-tunnel-1[1] ),
          'gtip_charon: returns one tunnel');

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_down);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
  _dhgrp => 'MODP_1536',
  _ikeencrypt => 'AES_CBC_256',
#  _ikeatime => 3315,
  _ikehash => 'HMAC_SHA1_96',
#  _ikelife => 28800,
  _ikeprf => 'PRF_HMAC_SHA1',
  _ikestate => 'up',
  _ikever   => '1',
  _lip => '192.168.100.128',
#  _lifetime => '3600',
  _lid => '192.168.100.128',
  _newestike => '3',
  _peerid => '192.168.100.129',
  _rip => '192.168.100.129',
  _rid => '192.168.100.129',
  _tunnelnum  => '1',
);

%th = get_tunnel_info();
is_deeply(join(' ', keys %th), qw( peer-192.168.100.129-tunnel-1[3] ),
    'gti_charon: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.100.129-tunnel-1[3]'},
                            keys %expected_th),
          \%expected_th, 'charon_up_down: %th matches');

%th = get_tunnel_info_peer('192.168.100.129');
is_deeply(join(' ', keys %th), qw( peer-192.168.100.129-tunnel-1[3] ),
    'gtip_charon: returns one tunnel');


mock_capture_retval('ip -s xfrm state list spi 0xc02b62a8',
                    \@ip_xfrm_state_list_spi_unused);
my %expected_data = (
    '_current_add' => 4415,
    '_config_expire_add' => '3600',
);

my %data = get_xfrm_spi_lifetimes('c02b62a8');
is_deeply(\%data, \%expected_data, 'unused lifetimes match');

mock_capture_retval('ip -s xfrm state list spi 0xc02b62a8',
                    \@ip_xfrm_state_list_spi);
%expected_data = (
    '_current_add' => 1800,
    '_config_expire_add' => '3600',
);
%data = get_xfrm_spi_lifetimes('c02b62a8');
is_deeply(\%data, \%expected_data, 'lifetimes match');

%expected_data = (
    'authby' => 'secret',
    'auto' => 'start',
    'compress' => 'no',
    'esp' => 'aes256-sha1!',
    'ike' => 'aes256-sha1-modp1536!',
    'ikelifetime' => '28800s',
    'keyingtries' => '%forever',
    'keylife' => '3600s',
    'left' => '192.168.100.7',
    'leftsubnet' => '192.168.248.0/24',
    'rekeymargin' => '540s',
    'right' => '192.168.100.6',
    'rightsubnet' => '192.168.40.0/24',
    'test' => '',
    'type' => 'tunnel',
);
%data = get_config_by_conn('peer-192.168.100.6-tunnel-1');
is_deeply(\%data, \%expected_data, 'conn config matches');
%expected_data = ( );
%data = get_config_by_conn('peer-11:1::2-tunnel-');
is_deeply(\%data, \%expected_data, 'conn config empty');


mock_capture_retval('ip -s xfrm state list spi 0xc74a030d',
                    \@ip_xfrm_state_list_spi);
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_up);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
#    '_atime' => 1800,
    '_ikeencrypt' => 'AES_CBC_256',
#    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => '28800',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_lid' => '192.168.100.7',
    '_lip' => '192.168.100.7',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_newestike' => '11',
    '_peerid' => '192.168.100.6',
    '_pfsgrp' => 'n/a',
    '_rid' => '192.168.100.6',
    '_rip' => '192.168.100.6',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_tunnelnum' => '1'
);

BEGIN {
    *CORE::GLOBAL::time = sub {
        return 1431341248 + 1800;
    }
}

%th = get_tunnel_info();

is_deeply([ sort keys %th], [ qw( peer-192.168.100.6-tunnel-1[11] peer-192.168.100.6-tunnel-1{21} ) ],
    'gti_charon: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.100.6-tunnel-1[11]'},
                            keys %expected_th),
          \%expected_th, 'charon_up_up: %th matches');

%th = get_tunnel_info_peer('192.168.100.6');
is_deeply([ sort keys %th], [ qw( peer-192.168.100.6-tunnel-1[11] peer-192.168.100.6-tunnel-1{21} ) ],
    'gtip_charon: returns one tunnel');

# test for vti interfaces
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_vti_up_up);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
    '_encryption' => 'AES_CBC_256',
    '_atime' => 1800,
    '_hash' => 'HMAC_SHA1_96',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '12445020',
    '_inspi' => 'c965452c',
    '_lca' => undef,
    '_lid' => '192.168.248.236',
    '_lifetime' => '3600',
    '_lip' => '192.168.248.236',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '0.0.0.0/0',
    '_natt' => 0,
    '_newestike' => '345',
    '_newestspi' => '1',
    '_outbytes' => '12446448',
    '_outspi' => 'c74a030d',
    '_peerid' => '192.168.248.248',
    '_pfsgrp' => 'n/a',
    '_rca' => undef,
    '_rid' => '192.168.248.248',
    '_rip' => '192.168.248.248',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '0.0.0.0/0',
    '_state' => 'up',
    '_tunnelnum' => 'vti'
);

%th = get_tunnel_info();
is_deeply([ sort keys %th], [ qw( peer-192.168.248.248-tunnel-vti[345] peer-192.168.248.248-tunnel-vti{1} ) ],
    'gti_charon_vti: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-192.168.248.248-tunnel-vti{1}'},
                            keys %expected_th),
          \%expected_th, 'charon_vti_up_up: %th matches');

%th = get_tunnel_info_peer('192.168.248.248');
is_deeply([ sort keys %th], [ qw( peer-192.168.248.248-tunnel-vti[345] peer-192.168.248.248-tunnel-vti{1} ) ],
    'gtip_charon_vti: returns one tunnel');

# test for child-sa dhgroup
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_dhgroup);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
    '_encryption' => 'AES_CBC_256',
    '_atime' => 1800,
    '_hash' => 'HMAC_SHA1_96',
    '_ikeencrypt' => 'AES_CBC_256',
#    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '12445020',
    '_inspi' => 'c965452c',
    '_lca' => undef,
    '_lid' => '192.168.248.236',
    '_lifetime' => '3600',
    '_lip' => '192.168.248.236',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '0.0.0.0/0',
    '_natdst' => 'n/a',
    '_natsrc' => 'n/a',
    '_natt' => 0,
    '_newestike' => '345',
    '_newestspi' => '1',
    '_outbytes' => '12446448',
    '_outspi' => 'c74a030d',
    '_peerid' => '192.168.248.248',
    '_pfsgrp' => 'MODP_1024',
    '_rca' => undef,
    '_rid' => '192.168.248.248',
    '_rip' => '192.168.248.248',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '0.0.0.0/0',
    '_state' => 'up',
    '_tunnelnum' => 'vti'
);

%th = get_tunnel_info();
is_deeply(scalar slice_hash($th{'peer-192.168.248.248-tunnel-vti{1}'},
                            keys %expected_th),
          \%expected_th, 'charon_dhggroup: %th matches');

# test for NAT
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_nat);
%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
#    '_atime' => 1800,
    '_ikeencrypt' => 'AES_CBC_256',
#    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_lca' => undef,
    '_lid' => '190.160.2.1',
    '_lip' => '190.160.2.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_natdst' => '500',
    '_natsrc' => '500',
    '_newestike' => '1',
    '_peerid' => '0.0.0.0',
#    '_pfsgrp' => 'n/a',
    '_rca' => undef,
    '_rid' => '190.160.3.2',
    '_rip' => '190.160.5.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply([ sort keys %th], [ qw( peer-0.0.0.0-tunnel-1[1] peer-0.0.0.0-tunnel-1{1} ) ],
    'gti_charon_nat: returns one tunnel');
is_deeply(scalar slice_hash($th{'peer-0.0.0.0-tunnel-1[1]'},
                            keys %expected_th),
          \%expected_th, 'charon_nat: %th matches');

%th = get_tunnel_info_peer('0.0.0.0');
is_deeply([ sort keys %th], [ qw( peer-0.0.0.0-tunnel-1[1] peer-0.0.0.0-tunnel-1{1} ) ],
    'gtip_charon_nat: returns one tunnel');

# test for two tunnels
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_two_tunnels);

mock_capture_retval('ip -s xfrm state list spi 0xc6c6150d',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);

%th = get_tunnel_info();

#use_ok('Vyatta::VPN::OPMode', qw( :all ) );
#mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);
#display_ipsec_sa_brief( \%th );

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1024',
    '_encryption' => '3DES_CBC',
    '_atime' => 1800,
    '_hash' => 'HMAC_MD5_96',
    '_ikeencrypt' => 'AES_CBC_256',
#    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'c53a2af9',
    '_lca' => undef,
    '_lid' => '190.160.2.1',
    '_lifetime' => '3600',
    '_lip' => '190.160.2.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '190.160.10.0/24',
    '_natdst' => 'n/a',
    '_natsrc' => 'n/a',
    '_natt' => 0,
    '_newestike' => '2',
    '_newestspi' => '2',
    '_outbytes' => '0',
    '_outspi' => 'c6c6150d',
    '_peerid' => '190.160.3.2',
    '_pfsgrp' => 'MODP_1024',
    '_rca' => undef,
    '_rid' => '190.160.3.2',
    '_rip' => '190.160.3.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '190.160.40.0/24',
    '_state' => 'up',
    '_tunnelnum' => '2'
);

is_deeply(scalar slice_hash($th{'peer-190.160.3.2-tunnel-2{2}'},
                            keys %expected_th),
          \%expected_th, 'charon_two_tunnelst: %th matches');

# test for two tunnels and one is down
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_two_tunnels_one_down);

mock_capture_retval('ip -s xfrm state list spi 0xc6c6150d',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);

%th = get_tunnel_info();


%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_ikestate' => 'down',
    '_atime' => 'n/a',
    '_ikever' => '1',
    '_lid' => '190.160.2.1',
    '_lip' => '190.160.2.1',
    '_lsnet' => '190.160.10.0/24',
    '_peerid' => '190.160.3.2',
    '_rid' => '190.160.3.2',
    '_rip' => '190.160.3.2',
    '_rsnet' => '190.160.40.0/24',
    '_tunnelnum' => '2'
);

is_deeply(scalar slice_hash($th{'peer-190.160.3.2-tunnel-2'},
                            keys %expected_th),
          \%expected_th, 'charon_two_tunnelst: %th matches');

# test auth x509 with remote-id dn
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_auth_x509_remote_id_dn);

mock_capture_retval('ip -s xfrm state list spi 0xc3f6c7cc',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);


%th = get_tunnel_info();


%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
#    '_atime' => '1800',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_lca' => undef,
    '_lid' => '@C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain',
    '_lip' => '11:1::1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_natdst' => 'n/a',
    '_natsrc' => 'n/a',
    '_newestike' => '2',
    '_peerid' => '11:1::2',
    '_pfsgrp' => 'n/a',
    '_rca' => undef,
    '_rid' => '@C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Client, E=me@myhost.mydomain',
    '_rip' => '11:1::2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_tunnelnum' => '2'
);
is_deeply(scalar slice_hash($th{'peer-11:1::2-tunnel-2[2]'},
                            keys %expected_th),
          \%expected_th, 'charon_auth_x509_remote_id_dn: %th matches');

#use_ok('Vyatta::VPN::OPMode', qw( :all ) );
#mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);
#display_ipsec_sa_brief( \%th );

# test for routed connections
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_routed_connections);

mock_capture_retval('ip -s xfrm state list spi 0x0001def5',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0x0001377b',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0x0001dd51',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc9a19b97',
                    \@ip_xfrm_state_list_spi);


%th = get_tunnel_info();

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'ECP_384',
    '_encryption' => 'AES_GCM_16_128',
    '_atime' => 1800,
    '_hash' => 'null',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA2_256_128',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA2_256',
    '_ikestate' => 'up',
    '_ikever' => '2',
    '_inbytes' => '0',
    '_inspi' => 'cec3b69f',
    '_lca' => undef,
    '_lid' => '192.0.71.1',
    '_lifetime' => '3600',
    '_lip' => '192.0.71.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '0.0.0.0/0',
    '_natt' => 0,
    '_newestike' => '11',
    '_newestspi' => '12',
    '_outbytes' => '0',
    '_outspi' => '0001def5',
    '_peerid' => '192.0.72.2',
    '_pfsgrp' => 'n/a',
    '_reqid' => '3',
    '_rca' => undef,
    '_rid' => '192.0.72.2',
    '_rip' => '192.0.72.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '0.0.0.0/0',
    '_state' => 'up',
    '_tunnelnum' => 'vti'
);

is_deeply(scalar slice_hash($th{'peer-192.0.72.2-tunnel-vti{12}'},
                            keys %expected_th),
          \%expected_th, 'charon_routed_connections: %th matches');

# test for shunted connections
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_shunted_connections);

mock_capture_retval('ip -s xfrm state list spi 0xcf5b3aa3',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);

%th = get_tunnel_info();

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1536',
    '_encryption' => 'AES_CBC_256',
    '_atime' => 1800,
    '_hash' => 'HMAC_SHA1_96',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'c3593216',
    '_lca' => undef,
    '_lid' => '10.10.2.2',
    '_lifetime' => '3600',
    '_lip' => '10.10.2.2',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '10.10.1.0/24',
    '_natt' => 0,
    '_newestike' => '6',
    '_newestspi' => '1',
    '_outbytes' => '0',
    '_outspi' => 'cf5b3aa3',
    '_peerid' => '10.10.2.3',
    '_pfsgrp' => 'MODP_1536',
    '_rca' => undef,
    '_reqid' => '1',
    '_rid' => '10.10.2.3',
    '_rip' => '10.10.2.3',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '10.10.3.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'
);

is_deeply(scalar slice_hash($th{'peer-10.10.2.3-tunnel-1{1}'},
                            keys %expected_th),
          \%expected_th, 'charon_shunted_connections: %th matches');

# test for 5.3.0+ and additionnal reqid output
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_5_3_0_alloc_reqid);

mock_capture_retval('ip -s xfrm state list spi 0xcb088a2b',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc5d8bacf',
                    \@ip_xfrm_state_list_spi);

%th = get_tunnel_info();

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_2048',
    '_encryption' => 'AES_CBC_256',
    '_atime' => '1800',
    '_hash' => 'HMAC_SHA1_96',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'c11192c8',
    '_lca' => undef,
    '_lid' => '10.10.2.3',
    '_lifetime' => '3600',
    '_lip' => '10.10.2.3',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '10.10.3.0/24',
    '_natt' => '0',
    '_newestike' => '558',
    '_newestspi' => '986',
    '_outbytes' => '0',
    '_outspi' => 'cb088a2b',
    '_peerid' => '10.10.2.2',
    '_pfsgrp' => 'MODP_2048',
    '_reqid' => '6',
    '_rca' => undef,
    '_rca' => undef,
    '_rid' => '10.10.2.2',
    '_rip' => '10.10.2.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '10.10.1.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'
);
is_deeply(scalar slice_hash($th{'peer-10.10.2.2-tunnel-1{986}'},
                            keys %expected_th),
          \%expected_th, 'charon_5_3_0_reqid: %th matches');


#$Data::Dumper::Sortkeys = 1;
#print Dumper(\%th) . "\n";

# test for IKEv2 status with pfs enabled and aes gcm encryption
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_up_aes256gcm128);
mock_capture_retval('ip -s xfrm state list spi 0xc9a8db96',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc667b512',
                    \@ip_xfrm_state_list_spi);

mock_read_file_retval('/etc/ipsec.conf', \@ipsec_conf_snippet);

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
#    '_atime' => '13',
    '_dhgrp' => 'MODP_1024',
    '_encryption' => 'AES_GCM_16_256',
    '_atime' => '1800',
    '_hash' => 'null',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'c9a8db96',
    '_lca' => undef,
    '_lid' => '10.10.1.1',
    '_lifetime' => '3600',
    '_lip' => '10.10.1.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '10.10.1.0/24',
    '_natt' => 0,
    '_newestike' => '10',
    '_newestspi' => '8',
    '_outbytes' => '0',
    '_outspi' => 'c667b512',
    '_peerid' => '10.10.1.2',
    '_pfsgrp' => 'MODP_1024',
    '_rca' => undef,
    '_rid' => '10.10.1.2',
    '_rip' => '10.10.1.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '10.10.3.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(scalar slice_hash($th{'peer-10.10.1.2-tunnel-1{8}'},
                            keys %expected_th),
          \%expected_th, 'charon_ikev2statusaes256gcm128: %th matches');

# test for IKEv2 status with ECP_* pfs enabled and aes gcm encryption
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_up_aes_pfs_ECP);
mock_capture_retval('ip -s xfrm state list spi 0xc47c36fe',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xc28acf7c',
                    \@ip_xfrm_state_list_spi);

mock_read_file_retval('/etc/ipsec.conf', \@ipsec_conf_snippet);

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
#    '_atime' => '13',
    '_dhgrp' => 'MODP_2048',
    '_encryption' => 'AES_GCM_16_128',
    '_atime' => '1800',
    '_hash' => 'null',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'c47c36fe',
    '_lca' => undef,
    '_lid' => '10.10.1.2',
    '_lifetime' => '3600',
    '_lip' => '10.10.1.2',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '10.10.3.0/24',
    '_natt' => 0,
    '_newestike' => '6',
    '_newestspi' => '3',
    '_outbytes' => '0',
    '_outspi' => 'c28acf7c',
    '_peerid' => '10.10.1.1',
    '_pfsgrp' => 'ECP_256',
    '_rca' => undef,
    '_rid' => '10.10.1.1',
    '_rip' => '10.10.1.1',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '10.10.4.0/24',
    '_state' => 'up',
    '_reqid' => '2',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(scalar slice_hash($th{'peer-10.10.1.1-tunnel-1{3}'},
                            keys %expected_th),
          \%expected_th, 'charon_ikev2statusaes128gcm128: %th matches');



# test handling of [protoco/port] parsing
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_proto_port);
mock_capture_retval('ip -s xfrm state list spi 0xc5232e9b',
                    \@ip_xfrm_state_list_spi);

mock_read_file_retval('/etc/ipsec.conf', \@ipsec_conf_snippet);

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_2048',
    '_encryption' => 'AES_CBC_256',
    '_atime' => 1800,
    '_hash' => 'HMAC_MD5_96',
    '_ikeencrypt' => 'AES_CBC_128',
    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_inbytes' => '0',
    '_inspi' => 'cf2b3689',
    '_lca' => undef,
    '_lid' => '190.160.2.1',
    '_lifetime' => '3600',
    '_lip' => '190.160.2.1',
    '_lport' => '1024',
    '_lproto' => 'tcp',
    '_lsnet' => '190.160.1.0/24',
    '_natt' => 0,
    '_newestike' => '3',
    '_newestspi' => '5',
    '_outbytes' => '0',
    '_outspi' => 'c5232e9b',
    '_peerid' => '190.160.3.2',
    '_pfsgrp' => 'MODP_2048',
    '_rca' => undef,
    '_reqid' => '3',
    '_rid' => '190.160.3.2',
    '_rip' => '190.160.3.2',
    '_rport' => '1024',
    '_rproto' => 'tcp',
    '_rsnet' => '190.160.4.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'
);

%th = get_tunnel_info();
is_deeply(scalar slice_hash($th{'peer-190.160.3.2-tunnel-1{5}'},
                            keys %expected_th),
          \%expected_th, 'charon_statusall_port_proto: %th matches');

# test ESP AES_GCM null hash parsing
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_esp_aes_gcm);
mock_capture_retval('ip -s xfrm state list spi 0xce78b763',
                    \@ip_xfrm_state_list_spi);

mock_capture_retval('ip -s xfrm state list spi 0xca005d50',
                    \@ip_xfrm_state_list_spi);

%expected_th = (
    %TestData_OPMode::TUNNEL_DEFAULTS,
    '_atime' => 1800,
    '_dhgrp' => 'MODP_1536',
    '_encryption' => 'AES_GCM_16_128',
    '_hash' => 'null',
    '_ikeencrypt' => 'AES_CBC_128',
    '_ikeatime' => 'n/a',
    '_ikehash' => 'HMAC_SHA2_256_128',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA2_256',
    '_ikestate' => 'up',
    '_ikever' => '2',
    '_inbytes' => '0',
    '_inspi' => 'ce78b763',
    '_lca' => undef,
    '_lid' => '190.160.2.1',
    '_lifetime' => '3600',
    '_lip' => '190.160.2.1',
    '_lport' => 'all',
    '_lproto' => 'all',
    '_lsnet' => '190.160.1.0/24',
    '_natt' => 0,
    '_newestike' => '1',
    '_newestspi' => '2',
    '_outbytes' => '0',
    '_outspi' => 'ca005d50',
    '_peerid' => '190.160.3.2',
    '_pfsgrp' => 'n/a',
    '_rca' => undef,
    '_reqid' => '1',
    '_rid' => '190.160.3.2',
    '_rip' => '190.160.3.2',
    '_rport' => 'all',
    '_rproto' => 'all',
    '_rsnet' => '190.160.4.0/24',
    '_state' => 'up',
    '_tunnelnum' => '1'

);

%th = get_tunnel_info();

is_deeply(scalar slice_hash($th{'peer-190.160.3.2-tunnel-1{2}'},
                            keys %expected_th),
          \%expected_th, 'charon_esp_aes_gcm_null_hash: %th matches');

# Test for hub tunnel leftover connections after cp /dev/null /etc/dmvpn.conf;
# ipsec reread; ipsec reload
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_hub_leftovers);

mock_capture_retval('ip -s xfrm state list spi 0xc539b748',
                    \@ip_xfrm_state_list_spi);

%th = get_tunnel_info_vpnprof();


%expected_th = (
    'vpnprof-tunnel-tun0[1]' => {
        '_atime' => 'n/a',
        '_dhgrp' => 'MODP_1536',
        '_encryption' => 'n/a',
        '_hash' => 'n/a',
        '_ikeencrypt' => 'AES_CBC_256',
        '_ikeatime' => '960',
        '_ikehash' => 'HMAC_SHA1_96',
        '_ikelife' => 'n/a',
        '_ikeprf' => 'PRF_HMAC_SHA1',
        '_ikestate' => 'up',
        '_ikever' => '1',
        '_inbytes' => 'n/a',
        '_inspi' => 'n/a',
        '_lca' => undef,
        '_lid' => '6.5.5.1',
        '_lifetime' => 'n/a',
        '_lip' => '6.5.5.1',
        '_lport' => 'all',
        '_lproto' => 'all',
        '_lsnet' => 'n/a',
        '_natdst' => '500',
        '_natsrc' => '500',
        '_natt' => 'n/a',
        '_newestike' => '1',
        '_newestspi' => 'n/a',
        '_outbytes' => 'n/a',
        '_outspi' => 'n/a',
        '_peerid' => '6.5.5.10',
        '_pfsgrp' => 'n/a',
        '_rca' => undef,
        '_reqid' => 'n/a',
        '_rid' => '6.5.5.10',
        '_rip' => '6.5.5.10',
        '_rport' => 'all',
        '_rproto' => 'all',
        '_rsnet' => 'n/a',
        '_state' => undef,
        '_tunnelnum' => 'tun0',
        '_said'      => undef,
        '_ikeexpire' => 'n/a'
    },
    'vpnprof-tunnel-tun0{1}' => {
        '_atime' => 'n/a',
        '_dhgrp' => 'MODP_1536',
        '_encryption' => 'n/a',
        '_hash' => 'n/a',
        '_ikeencrypt' => 'AES_CBC_256',
        '_ikeatime' => 'n/a',
        '_ikehash' => 'HMAC_SHA1_96',
        '_ikelife' => 'n/a',
        '_ikeprf' => 'PRF_HMAC_SHA1',
        '_ikestate' => 'up',
        '_ikever' => '1',
        '_inbytes' => 'n/a',
        '_inspi' => 'n/a',
        '_lca' => undef,
        '_lid' => '6.5.5.1',
        '_lifetime' => 'n/a',
        '_lip' => '6.5.5.1',
        '_lport' => 'all',
        '_lproto' => 'gre',
        '_lsnet' => '6.5.5.1/32',
        '_natdst' => 'n/a',
        '_natsrc' => 'n/a',
        '_natt' => 'n/a',
        '_newestike' => '1',
        '_newestspi' => 'n/a',
        '_outbytes' => 'n/a',
        '_outspi' => 'n/a',
        '_peerid' => '6.5.5.10',
        '_pfsgrp' => 'n/a',
        '_rca' => undef,
        '_reqid' => '1',
        '_rid' => '6.5.5.10',
        '_rip' => '6.5.5.10',
        '_rport' => 'all',
        '_rproto' => 'gre',
        '_rsnet' => '6.5.5.10/32',
        '_state' => undef,
        '_tunnelnum' => 'tun0',
        '_said'      => '1', 
        '_ikeexpire' => 'n/a'
    },
    'vpnprof-tunnel-tun0{2}' => {
        '_atime' => 1800,
        '_dhgrp' => 'MODP_1536',
        '_encryption' => 'AES_CBC_256',
        '_hash' => 'HMAC_SHA1_96',
        '_ikeencrypt' => 'AES_CBC_256',
        '_ikeatime' => 'n/a',
        '_ikehash' => 'HMAC_SHA1_96',
        '_ikelife' => 'n/a',
        '_ikeprf' => 'PRF_HMAC_SHA1',
        '_ikestate' => 'up',
        '_ikever' => '1',
        '_inbytes' => '0',
        '_inspi' => 'c1ab3622',
        '_lca' => undef,
        '_lid' => '6.5.5.1',
        '_lifetime' => '3600',
        '_lip' => '6.5.5.1',
        '_lport' => 'all',
        '_lproto' => 'gre',
        '_lsnet' => '6.5.5.1/32',
        '_natdst' => 'n/a',
        '_natsrc' => 'n/a',
        '_natt' => 0,
        '_newestike' => '1',
        '_newestspi' => '2',
        '_outbytes' => '0',
        '_outspi' => 'c539b748',
        '_peerid' => '6.5.5.10',
        '_pfsgrp' => 'MODP_1536',
        '_rca' => undef,
        '_reqid' => '1',
        '_rid' => '6.5.5.10',
        '_rip' => '6.5.5.10',
        '_rport' => 'all',
        '_rproto' => 'gre',
        '_rsnet' => '6.5.5.10/32',
        '_state' => 'up',
        '_tunnelnum' => 'tun0',
        '_said'      => '2',
        '_ikeexpire' => 'n/a'
    }
);

use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
print Dumper(\%th) . "\n";

is_deeply(\%th, \%expected_th, 'charon_hub_leftovers: %th matches');
