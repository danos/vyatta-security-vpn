#!/usr/bin/perl -w

# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use File::Basename;
use Cwd 'abs_path';
use IO::String;

use lib abs_path(dirname(__FILE__) . '/../lib');

use TestData_OPMode;
use Test::More 'no_plan';
use Test::MockObject;

use lib dirname(__FILE__);

my $mock = Test::MockObject->new();
$mock->fake_module('Vyatta::Config');
$mock->fake_module('Vyatta::Configd');
$mock->fake_module('NetAddr::IP');

my $mock_dp = Test::MockObject->new();
$mock_dp->fake_module('Test::Vyatta::DataplaneSocket');
$mock_dp->fake_new('Test::Vyatta::DataplaneSocket');

my $mock_sock_execute;
$mock_dp->set_bound('execute', \$mock_sock_execute);

my $mockd = Test::MockObject->new();
$mockd->fake_module('Vyatta::Dataplane',
                    setup_fabric_conns => sub {
                        return ( [ 0 ],
                                 [ Test::Vyatta::DataplaneSocket->new() ] );
                    });

use_ok('Vyatta::VPN::OPMode', qw( :all ) );
use Test::Vyatta::MockSimple qw(mock_capture_retval);

is(conv_hash('AUTH_AES_XCBC_96'), 'aesxcbc', 'conv_hash: aesxcbc');
is(conv_hash('HMAC_MD5_96'), 'md5', 'conv_hash: md5');
is(conv_hash('HMAC_SHA1_96'), 'sha1', 'conv_hash: sha1');
is(conv_hash('AUTH_HMAC_SHA1_160'), 'sha1_160', 'conv_hash: sha1_160');
is(conv_hash('HMAC_SHA2_256_128'), 'sha2_256', 'conv_hash: sha2_256');
is(conv_hash('HMAC_SHA2_384_192'), 'sha2_384', 'conv_hash: sha2_384');
is(conv_hash('HMAC_SHA2_512_256'), 'sha2_512', 'conv_hash: sha2_512');
is(conv_hash(''), '', 'conv_hash: empty');
is(conv_hash('n/a'), 'n/a', 'conv_hash: n/a');

is(conv_natt(0), 'no', 'conv_natt: numeric 0');
is(conv_natt('0'), 'no', 'conv_natt: string 0');
is(conv_natt('1'), 'yes', 'conv_natt: string 1');
is(conv_natt('n/a'), 'no', 'conv_natt: n/a');

is(conv_id_rev(), undef, 'conv_id_rev: undef');
is(conv_id_rev(undef), undef, 'conv_id_rev: undef input');
is(conv_id_rev(''), '', 'conv_id_rev: empty string');
is(conv_id_rev('192.168.0.1'), '192.168.0.1', 'conv_id_rev: IP address');
is(conv_id_rev('any'), 'any', 'conv_id_rev: any');
is(conv_id_rev('@moon.strongswan.org'), 'moon.strongswan.org',
   'conv_id_rev: ID');
is_deeply(\@{[ conv_id_rev(qw( 192.168.0.1 any @moon.strongswan.org )) ]},
   [ '192.168.0.1', 'any', 'moon.strongswan.org' ], 'conv_id_rev: array');


my @peers = qw( 1.0.0.2-1.0.0.3 1.0.0.1-1.0.0.3 0.0.0.0-1.0.0.3 );
is_deeply(
    [ peerSort( @peers ) ],
    [ qw( 0.0.0.0-1.0.0.3 1.0.0.1-1.0.0.3 1.0.0.2-1.0.0.3 ) ],
    'peerSort: sorts list of peers by peer IP (peerip-localip)'
);

@peers = qw( 0.0.0.0-1.0.0.3 0.0.0.0-1.0.0.2 0.0.0.0-1.0.0.4 );
is_deeply([ peerSort( @peers ) ], \@peers,
          'peerSort: doesn\'t care for local IP (1)');
@peers = qw( 0.0.0.0 0.0.0.0- 0.0.0.0-@test 0.0.0.0-any 0.0.0.0-n/a );
is_deeply([ peerSort( @peers ) ], \@peers,
          'peerSort: doesn\'t care for local IP (2)');

@peers = qw( @abcd-1.0.0.3 @aaaab-1.0.0.3 @aaaaa-1.0.0.3 );
is_deeply(
    [ peerSort( @peers ) ],
    [ qw( @aaaaa-1.0.0.3 @aaaab-1.0.0.3 @abcd-1.0.0.3 ) ],
    'peerSort: sorts list of peers by string value');

@peers = qw( @aaaab-1.0.0.3 11:1::4-11:1::1 11:1::5-11:1::1 11:1::2-11:1::1 @aaaaa-1.0.0.3 11.1.0.5-11.1.0.1 11.1.0.2-11.1.0.1 );
is_deeply(
    [ peerSort( @peers ) ],
    [ qw (11.1.0.2-11.1.0.1 11.1.0.5-11.1.0.1 11:1::2-11:1::1 11:1::4-11:1::1 11:1::5-11:1::1 @aaaaa-1.0.0.3 @aaaab-1.0.0.3) ],
    'peerSort: sorts list of mixed peers (IPv4, IPv6, and named)');


my @tunnels;

push( @tunnels, [( 2, 'up')] );
push( @tunnels, [( 3, 'up')] );
push( @tunnels, [( 1, 'down')] );

is_deeply(
    [ tunSort( @tunnels ) ],
    [ [( 1, 'down')], [( 2, 'up')], [( 3, 'up')] ],
    'tunSort: sorts list of mixed tunnels');


{
    no warnings qw(once redefine);
    local *Vyatta::VPN::OPMode::get_config_tunnel_desc =
    sub {
        my (@peers) = @_;

        my %hash = map {
        $_ =~ /^192\.168\./xms ? ( $_ => 'Oink!' ) : ( )
        } @peers;

        return %hash;
    };

    my %expected_tunnel_infos = (
        'peer-10.10.100.128-tunnel-1'   => { '_peerid' => '10.10.100.128' },
        'peer-192.168.100.128-tunnel-1' =>
        {
            '_peerid' => '192.168.100.128',
            '_desc' => 'Oink!',
        },
    );
    my %tunnel_infos = (
        'peer-10.10.100.128-tunnel-1'   => { '_peerid' => '10.10.100.128' },
        'peer-192.168.100.128-tunnel-1' => { '_peerid' => '192.168.100.128' },
    );
    add_tunnel_info_description(\%tunnel_infos);
    is_deeply(\%tunnel_infos, \%expected_tunnel_infos,
          'add_tunnel_info_description: add _desc to 192.168.* peers');
}

SKIP: {
    use lib dirname(__FILE__);
    use TestData_OPMode;

    no warnings qw(once redefine);
    local *Vyatta::VPN::OPMode::get_config_tunnel_desc =
    sub {
        my (@peers) = @_;

        my %hash = map {
        $_ =~ /^192\.168\./xms ? ( $_ => 'Oink!' ) : ( )
        } @peers;

        return %hash;
    };

    my %expected_th = (
        %TestData_OPMode::TUNNEL_DEFAULTS,
        '_dhgrp' => 'MODP_1536',
        '_encryption' => 'AES_CBC_256',
        '_atime' => 815,
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
        '_tunnelnum' => '1',
        '_said'      => '#4'
    );

    {
        my ($out, $err);
        my $io_out = IO::String->new($out);
        my $io_err = IO::String->new($err);

        local *STDOUT = $io_out;
        local *STDERR = $io_err;

        no warnings qw(once redefine);
        local *Vyatta::VPN::OPMode::get_all_tunnels = sub {
            return ( 'peer-192.168.100.128-tunnel-1{4}' => \%expected_th );
        };
        $mock_sock_execute = join("\n", @vplsh_ipsec_sad);

        show_ipsec_sa();

        # 3600 - 2785 = 815
        like($out, qr{842.0/842.0\ +  aes256\ +  sha1\ +  5\ + 815\ + 3600}, "a-time is correct");
        is($err, '', "No error output");
    }

    my %expected_th2 = %expected_th;
    $expected_th2{_lifetime} = $expected_th2{_atime} = 'n/a';

    {
        my ($out, $err);
        my $io_out = IO::String->new($out);
        my $io_err = IO::String->new($err);

        local *STDOUT = $io_out;
        local *STDERR = $io_err;

        no warnings qw(once redefine);
        local *Vyatta::VPN::OPMode::get_tunnel_info_peer = sub {
            return ( 'peer-192.168.100.128-tunnel-1{4}' => \%expected_th2 );
        };
        $mock_sock_execute = join("\n", @vplsh_ipsec_sad);

        show_ipsec_sa_peer('192.168.100.128');

		mock_capture_retval("/opt/vyatta/bin/vplsh -l -c 'ipsec sad'", \@vplsh_ipsec_sad);

        like($out, qr{sha1\ + 5\ + n/a\ + n/a}, "a-time is n/a");
        is($err, '', "No error output");
    }

    no warnings qw(once redefine);
    local *Vyatta::VPN::OPMode::get_all_tunnels = sub {
        return ( 'peer-192.168.100.128-tunnel-1' => \%expected_th );
    };

    # comment next line to see output on console
    skip 'No way to capture display_* output right now', 1;

    show_ipsec_sa_stats();
}
$mock_sock_execute = join("\n", @vplsh_ipsec_sad_blocked);

my %policies = get_dataplane_ipsec_sad_sas();

my %expected_policies = (
	'ccead32f' => {
		'bytes' => 0,
		'packets' => 1234,
		'blocked' => 0
	},
	'c5eef99b' => {
		'bytes' => 4321,
		'packets' => 0,
		'blocked' => 1
	}
);

is_deeply(\%policies, \%expected_policies, 'compare vplsh ipsec sad hashs for blocked and un-blocked SPIs');
