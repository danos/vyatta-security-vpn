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

use lib dirname(__FILE__);

my $mock = Test::MockObject->new();
$mock->fake_module('Vyatta::Config');
$mock->fake_module('Vyatta::Configd');
$mock->fake_module('NetAddr::IP');

use_ok('Vyatta::VPN::Charon', qw( :ALL ) );

use lib dirname(__FILE__);
use TestData_OPMode qw( %TUNNEL_DEFAULTS @ip_xfrm_state_list_spi_unused @ipsec_conf_snippet @vplsh_ipsec_sad );
use TestData_Prof_OPMode qw( @pluto_ipsec_statusall_up_up @charon_ipsec_statusall_up_up @charon_ipsec_statusall_hub @charon_ipsec_statusall_peerid @charon_ipsec_statusall_hub_two_spokes @charon_ipsec_statusall_hub_two_profiles);

is_deeply([ _make_vpnprof_connection_matcher()->(
    $charon_ipsec_statusall_up_up[12]) ],
	  [ q(vpnprof-tunnel-tun999),
	    { '_tunnelnum' => 'tun999', '_peerid' => undef } ],
	  'vpnprof connection matcher HUB');

is_deeply([ _make_vpnprof_connection_matcher()->(
    $charon_ipsec_statusall_up_up[15]) ],
	  [ q(tun999-192.168.103.12-to-192.168.103.11),
	    { '_tunnelnum' => 'tun999', '_peerid' => '192.168.103.11' } ],
	  'vpnprof connection matcher SPOKE');

use Test::Vyatta::MockSimple qw(mock_capture_retval mock_read_file_retval);
mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_up);
my %expected_th = (
    %TUNNEL_DEFAULTS,
    '_ikelife' => 'n/a',
    '_ikestate' => 'down',
    '_ikeatime' => 'n/a',
    '_ikever' => '1',
    '_lid' => '192.168.103.12',
    '_lifetime' => 'n/a',
    '_lip' => '192.168.103.12',
    '_lport' => 'all',
    '_lproto' => 'gre',
    '_lsnet' => 'dynamic',
    '_natt' => 'n/a',
    '_newestike' => 'n/a',
    '_newestspi' => 'n/a',
    '_peerid' => undef,
    '_rid' => 'n/a',
    '_rip' => '%any',
    '_rport' => 'all',
    '_rproto' => 'gre',
    '_rsnet' => 'dynamic',
    '_tunnelnum' => 'tun999',
    '_said'      => undef
);

{
    no warnings 'redefine';
    local *Vyatta::VPN::Charon::get_tunnel_id_by_address =
        sub { return 'tun999' };

    mock_capture_retval('ip -s xfrm state list spi 0xc983bf65',
                    \@ip_xfrm_state_list_spi_unused);

    mock_read_file_retval('/etc/ipsec.conf', \@ipsec_conf_snippet);

    my %th = get_tunnel_info_vpnprof();

    is_deeply([ sort keys %th ],
              [ qw( tun999-192.168.103.12-to-192.168.103.11[1] tun999-192.168.103.12-to-192.168.103.11{1} vpnprof-tunnel-tun999 ) ],
              'gti returns two tunnels');
    is_deeply($th{'vpnprof-tunnel-tun999'},
              \%expected_th, 'down_down');


#    use Data::Dumper;
#    $Data::Dumper::Sortkeys = 1;
#    print Dumper(\%th) . "\n";
}

{
    no warnings qw(once redefine);
    local *Vyatta::VPN::Charon::get_tunnel_id_by_address =
        sub { return 'tun999' };

    local *Vyatta::VPN::Charon::get_tunnel_id_by_profile =
        sub {
            my @tunnels = qw(tun1 tun999);
            return @tunnels;
        };

    local *Vyatta::VPN::Charon::get_address_by_tunnel_id =
        sub {
            my ($tun) = @_;
            my @addresses;
            push @addresses, qw(192.168.1.234) if $tun eq 'tun1';
            push @addresses, qw(192.168.103.12) if $tun eq 'tun999';
            return @addresses;
        };

    mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_up_up);

    my %th = get_tunnel_info_profile('oink');

    is_deeply([ sort keys %th ],
              [ qw( tun999-192.168.103.12-to-192.168.103.11[1] tun999-192.168.103.12-to-192.168.103.11{1} vpnprof-tunnel-tun999 ) ],
              'gti returns two tunnels');
}

BEGIN {
    *CORE::GLOBAL::time = sub {
        return 1431338633 + 1800;
    }
}

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_hub);
%expected_th = (
    %TUNNEL_DEFAULTS,
   '_dhgrp' => 'MODP_1024',
   '_ikeencrypt' => 'AES_CBC_128',
   '_ikehash' => 'HMAC_SHA1_96',
   '_ikeprf' => 'PRF_HMAC_SHA1',
   '_ikeatime' => '79200',
   '_ikestate' => 'up',
   '_ikever' => '1',
   '_lca' => undef,
   '_lid' => '5.5.5.64',
   '_lifetime' => 'n/a',
   '_lip' => '5.5.5.64',
   '_lport' => 'all',
   '_lproto' => 'all',
   '_natdst' => '4500',
   '_natsrc' => '4500',
   '_newestike' => '4',
   '_peerid' => '5.5.5.74',
   '_rca' => undef,
   '_rid' => '10.10.4.74',
   '_rip' => '5.5.5.74',
   '_rport' => 'all',
   '_rproto' => 'all',
   '_tunnelnum' => 'tun1',
   '_said'      => undef
);

{
    mock_capture_retval('ip -s xfrm state list spi 0x95814024',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xdcbfdbfc',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xcd309252',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xc515b62b',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xcd9505bc',
                    \@ip_xfrm_state_list_spi_unused);


    my %th = get_tunnel_info_vpnprof();

    is_deeply([ sort keys %th ],
              [ qw( vpnprof-tunnel-tun0[5] vpnprof-tunnel-tun0{1965} vpnprof-tunnel-tun0{1967} vpnprof-tunnel-tun1[11] vpnprof-tunnel-tun1[13] vpnprof-tunnel-tun1[14] vpnprof-tunnel-tun1[4] vpnprof-tunnel-tun1{1925} vpnprof-tunnel-tun1{1962} vpnprof-tunnel-tun1{1963} vpnprof-tunnel-tun1{1966} ) ],
              'gti returns two tunnels');
    is_deeply($th{'vpnprof-tunnel-tun1[4]'},
              \%expected_th, '2nd spoke tunnel hash matches');


   #use Data::Dumper;
   #$Data::Dumper::Sortkeys = 1;
   #print Dumper(\%th) . "\n";

   #use_ok('Vyatta::VPN::OPMode', qw( :all ) );
   #mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

   #add_tunnel_info_description( \%th );
   #display_ipsec_sa_brief( \%th );

}

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_peerid);
%expected_th = (
    %TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1024',
    '_ikeencrypt' => 'AES_CBC_256',
    '_ikeatime' => '67',
    '_ikehash' => 'HMAC_SHA1_96',
    '_ikelife' => 'n/a',
    '_ikeprf' => 'PRF_HMAC_SHA1',
    '_ikestate' => 'up',
    '_ikever' => '1',
    '_lca' => undef,
    '_lid' => '101.1.1.1',
    '_lip' => '101.1.1.1',
    '_lport' => 'all',
    '_natdst' => '500',
    '_natsrc' => '500',
    '_newestike' => '225',
    '_peerid' => '109.1.1.1',
    '_rca' => undef,
    '_rid' => '109.1.1.1',
    '_rip' => '109.1.1.1',
    '_rport' => 'all',
    '_tunnelnum' => 'tun0',
    '_said'      => undef
);

{
    mock_capture_retval('ip -s xfrm state list spi 0xc5ae5657',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xc095e95e',
                    \@ip_xfrm_state_list_spi_unused);


    my %th = get_tunnel_info_vpnprof();

    is_deeply([ sort keys %th ],
              [ qw( tun0-101.1.1.1-to-102.1.1.1 tun0-101.1.1.1-to-108.1.1.1[224] tun0-101.1.1.1-to-108.1.1.1{1} tun0-101.1.1.1-to-109.1.1.1[225] tun0-101.1.1.1-to-109.1.1.1{2} vpnprof-tunnel-tun0 ) ],
              'gti number of tunnel matches');
    is_deeply($th{'tun0-101.1.1.1-to-109.1.1.1[225]'},
              \%expected_th, 'third spoke tunnel hash matches');

    my %th_peer = get_tunnel_info_peer('108.1.1.1');
    is_deeply([ sort keys %th_peer ],
              [ qw( tun0-101.1.1.1-to-108.1.1.1[224] tun0-101.1.1.1-to-108.1.1.1{1} ) ],
              'gtip returns one dmvpn tunnel');

    #use_ok('Vyatta::VPN::OPMode', qw( :all ) );
    #mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

    #add_tunnel_info_description( \%th_peer );
    #display_ike_sa_brief( \%th_peer );
}

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_hub_two_spokes);
%expected_th = (
    %TUNNEL_DEFAULTS,
    '_dhgrp' => 'MODP_1024',
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
    '_lca' => undef,
    '_lid' => '101.1.1.1',
    '_lifetime' => '3600',
    '_lip' => '101.1.1.1',
    '_lport' => 'all',
    '_lproto' => 'gre',
    '_lsnet' => 'dynamic',
    '_natdst' => '500',
    '_natsrc' => '500',
    '_natt' => 0,
    '_newestike' => '225',
    '_newestspi' => '2',
    '_outbytes' => '0',
    '_peerid' => '109.1.1.1',
    '_pfsgrp' => 'MODP_1024',
    '_rca' => undef,
    '_reqid' => '2',
    '_rid' => '109.1.1.1',
    '_rip' => '109.1.1.1',
    '_rport' => 'all',
    '_rproto' => 'gre',
    '_rsnet' => '0.0.0.0/0',
    '_state' => 'up',
    '_tunnelnum' => 'tun0',
    '_said'      => '2'
);

{
    mock_capture_retval('ip -s xfrm state list spi 0xcb56eea3',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xcc9f8a7f',
                    \@ip_xfrm_state_list_spi_unused);

    my %th = get_tunnel_info_vpnprof();

    #use Data::Dumper;
    #$Data::Dumper::Sortkeys = 1;
    #print Dumper(\%th) . "\n";

    #use_ok('Vyatta::VPN::OPMode', qw( :all ) );
    #mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

    #add_tunnel_info_description( \%th );
    #display_ike_sa_brief( \%th );
    #display_ipsec_sa_brief( \%th );

   # One can mimic a show-command based on a test-fixture like this:
   # (example for: show vpn ipsec sa)
   #
   #use_ok('Vyatta::VPN::OPMode', qw( :all ) );
   #mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

   #add_tunnel_info_description( \%th );
   #display_ipsec_sa_brief( \%th );
    is_deeply([ sort keys %th ],
              [ qw( vpnprof-tunnel-tun0[1] vpnprof-tunnel-tun0[2] vpnprof-tunnel-tun0{1} vpnprof-tunnel-tun0{2} ) ],
              'two IKE_SAs, two CHILD_SAs');

}

mock_capture_retval('ipsec statusall', \@charon_ipsec_statusall_hub_two_profiles);
%expected_th = (
    %TUNNEL_DEFAULTS,
);

{
    mock_capture_retval('ip -s xfrm state list spi 0xceb2eadd',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xceac9f5c',
                    \@ip_xfrm_state_list_spi_unused);

    mock_capture_retval('ip -s xfrm state list spi 0xc6a144ed',
                    \@ip_xfrm_state_list_spi_unused);


    my %th = get_tunnel_info_vpnprof();

    #use_ok('Vyatta::VPN::OPMode', qw( :all ) );
    #mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

    #add_tunnel_info_description( \%th );
    #display_ipsec_sa_detail( \%th );

    is_deeply([ sort keys %th ],
              [ qw( vpnprof-tunnel-tun0 vpnprof-tunnel-tun1[7] vpnprof-tunnel-tun1[8] vpnprof-tunnel-tun1[9] vpnprof-tunnel-tun1{86} vpnprof-tunnel-tun1{87} vpnprof-tunnel-tun1{88} vpnprof-tunnel-tun1{89} ) ],
              'three IKE_SAs, three CHILD_SAs');


    %th = get_tunnel_info_peer( '5.5.5.61' );
    #display_ipsec_sa_brief( \%th );

    is_deeply([ sort keys %th ],
              [ qw( vpnprof-tunnel-tun1[9] vpnprof-tunnel-tun1{86} vpnprof-tunnel-tun1{89} ) ],
              'dmvpn gti peer failed');

}

SKIP: {
    # comment next line to see output on console
    skip 'No way to capture display_* output right now', 1;

    my %expected_th = (
        '100.100.100.1-to-100.100.100.200' => {
            %TUNNEL_DEFAULTS,
            '_dhgrp' => 'MODP_1024',
            '_encryption' => 'AES_CBC_256',
            '_expire' => 2020,
            '_hash' => 'HMAC_SHA1',
            '_ikeencrypt' => 'AES_CBC_256',
            '_ikeexpire' => 4431,
            '_ikehash' => 'HMAC_SHA1',
            '_ikelife' => 10800,
            '_ikestate' => 'up',
            '_inbytes' => '882',
            '_inspi' => 'cc56f45b',
            '_lca' => undef,
            '_lid' => '192.168.103.12',
            '_lifetime' => 3600,
            '_lip' => '192.168.103.12',
            '_lport' => '0',
            '_lproto' => 'gre',
            '_lsnet' => 'n/a',
            '_natdst' => 'n/a',
            '_natsrc' => 'n/a',
            '_natt' => 0,
            '_newestike' => '#80',
            '_newestspi' => '#84',
            '_outbytes' => '782',
            '_outspi' => 'c08bdbcf',
            '_peerid' => undef,
            '_pfsgrp' => '<Phase1>',
            '_rca' => undef,
            '_rid' => '192.168.103.11',
            '_rip' => '192.168.103.11',
            '_rport' => '0',
            '_rproto' => 'gre',
            '_rsnet' => 'n/a',
            '_state' => 'up',
            '_tunnelnum' => 'tun999'
        },
        'vpnprof-tunnel-tun999' => {
            %TUNNEL_DEFAULTS,
            '_dhgrp' => 'n/a',
            '_encryption' => 'n/a',
            '_expire' => 'n/a',
            '_hash' => 'n/a',
            '_ikeencrypt' => 'n/a',
            '_ikeatime' => 'n/a',
            '_ikehash' => 'n/a',
            '_ikelife' => '3600',
            '_ikestate' => 'down',
            '_inbytes' => 'n/a',
            '_inspi' => 'n/a',
            '_lca' => undef,
            '_lid' => '192.168.103.12',
            '_lifetime' => '1800',
            '_lip' => '192.168.103.12',
            '_lport' => '0',
            '_lproto' => 'gre',
            '_lsnet' => 'n/a',
            '_natdst' => 'n/a',
            '_natsrc' => 'n/a',
            '_natt' => 0,
            '_newestike' => '#0',
            '_newestspi' => '#0',
            '_outbytes' => 'n/a',
            '_outspi' => 'n/a',
            '_peerid' => undef,
            '_pfsgrp' => 'n/a',
            '_rca' => undef,
            '_rid' => 'any',
            '_rip' => '%any',
            '_rport' => '0',
            '_rproto' => 'gre',
            '_rsnet' => 'n/a',
            '_tunnelnum' => 'tun999'
        }
    );

    no warnings qw(once redefine);
    local *Vyatta::VPN::OPMode::get_tunnel_info = sub {
        return %expected_th;
    };

    show_ipsec_sa_stats();
}
