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

use Test::More 'no_plan';  # or use Test::More 'no_plan';
use Test::Exception;
use Test::MockObject;

my ($value, $orig_value);

my $mock = Test::MockObject->new();
$mock->fake_module('Vyatta::Config',
                       returnOrigValue => sub { return $orig_value; },
                       returnValue => sub { return $value; },
                  );
$mock->fake_new('Vyatta::Config');
$mock->fake_new('Vyatta::Configd');
$mock->fake_module('NetAddr::IP');

$mock->set_true('setLevel');
my $configMode;
$mock->set_bound('inSession', \$configMode);

# for whatever reason, this doesn't export $LOCAL_KEY_FILE_DEFAULT
use_ok('Vyatta::VPN::Config', qw(:ALL));

# In our test scenario, the committed config doesn't have an explicitly
# set rsa-key local-key file value, but one has been configured (but
# not committed). Thus calling rsa_get_local_key_file() would return
# the configured value in config mode, and the default value otherwise.
($value, $orig_value) = ('/tmp/test.key', undef);

# out of config mode, we should return default (if no value is set)
$configMode = 0;
is(rsa_get_local_key_file(), $Vyatta::VPN::Config::LOCAL_KEY_FILE_DEFAULT);

# now pretend we have a configured/committed value
$orig_value = '/config/ipsec.d/rsa-keys/west.key';
is(rsa_get_local_key_file(), $orig_value);

# now test for configured/uncommitted value in config mode
$configMode = 1;
is(rsa_get_local_key_file(), $value);

dies_ok { validate_local_key_file('') };
dies_ok { validate_local_key_file('./tmp/test.key') };
dies_ok { validate_local_key_file('/tmp/test.key!') };
dies_ok { validate_local_key_file('/tmp//test.key') };
dies_ok { validate_local_key_file('/') };
lives_and { ok(validate_local_key_file(
		   $Vyatta::VPN::Config::LOCAL_KEY_FILE_DEFAULT))
};

SKIP: {
skip 'No way to adequately mock Vyatta::Config right now', 1;

is(get_tunnel_id_by_address('100.100.100.1'), 'tun999', 'tunnelid matches');

# forcing list context makes the unittest short
is((get_address_by_tunnel_id('tun999'))[0],
   '100.100.100.1', 'address matches');

# forcing list context makes the unittest short
is((get_tunnel_id_by_profile('DMVPN'))[0],
   'tun999', 'tunnelid matches (2)');
}

my $effective_value;
$mock->set_bound('returnEffectiveValue', \$effective_value);

my %expected_th = ();
my %th = get_config_tunnel_desc( qw( unknown peer ) );
is_deeply(\%th, \%expected_th, 'get_config_tunnel_desc: empty tunnel');


$effective_value = 'Test description';
%expected_th = (
    '192.168.0.2' => 'Test description',
    '192.168.0.7' => 'Test description',
);
%th = get_config_tunnel_desc( keys %expected_th );
is_deeply(\%th, \%expected_th, 'get_config_tunnel_desc: found description');

my @expected_dhgroups = ( 'modp1536', 'modp1024' );
my @dhgroups = get_ike_modp_default(undef);
is_deeply(\@dhgroups, \@expected_dhgroups, 'get_ike_modp_default: undef');
@dhgroups = get_ike_modp_default('');
is_deeply(\@dhgroups, \@expected_dhgroups, 'get_ike_modp_default: empty');
@expected_dhgroups = ( 'modp2048' );
@dhgroups = get_ike_modp_default('dh-group14');
is_deeply(\@dhgroups, \@expected_dhgroups, 'get_ike_modp_default: dh-group14');
@dhgroups = get_ike_modp_default('14');
is_deeply(\@dhgroups, \@expected_dhgroups, 'get_ike_modp_default: string 14');
@dhgroups = get_ike_modp_default(14);
is_deeply(\@dhgroups, \@expected_dhgroups, 'get_ike_modp_default: numeric 14');
dies_ok { scalar get_ike_modp_default() };
dies_ok { @dhgroups = get_ike_modp_default('oink') };

is(conv_protocol_all('all'), '%any');

is(conv_pfs_to_dh_group('disable'), '');
is(conv_pfs_to_dh_group('dh-group14'), 'modp2048');
dies_ok { conv_pfs_to_dh_group('enable') };

is(generate_conn_ike_proposal('aes128', 'sha1'),
   'aes128-sha1-modp1536,aes128-sha1-modp1024');
is(generate_conn_ike_proposal('aes128', 'sha1', ''),
   'aes128-sha1-modp1536,aes128-sha1-modp1024');
is(generate_conn_ike_proposal('aes128', 'sha1', undef),
   'aes128-sha1-modp1536,aes128-sha1-modp1024');
is(generate_conn_ike_proposal('aes128', 'sha1', '2'),
   'aes128-sha1-modp1024');
dies_ok { generate_conn_ike_proposal('aes128', 'sha1', 'oink') };
is(generate_conn_ike_proposal('aes128gcm128', 'null'),
   'aes128gcm128-modp1536,aes128gcm128-modp1024');
is(generate_conn_ike_proposal('aes128gcm128', 'null', 20),
   'aes128gcm128-ecp384');

is(generate_conn_esp('aes128', 'sha1'),
   'aes128-sha1');
is(generate_conn_esp('aes128', 'sha1', undef),
   'aes128-sha1');
is(generate_conn_esp('aes128', 'sha1', ''),
   'aes128-sha1');
is(generate_conn_esp('aes128', 'sha1', 'modp2048'),
   'aes128-sha1-modp2048');
is(generate_conn_esp('aes128gcm128', 'null', 'modp2048'),
   'aes128gcm128-modp2048');
is(generate_conn_esp('aes128gcm128', 'null'),
   'aes128gcm128');

#
# tests for charon logging content generator
#
use_ok('Vyatta::VPN::Config', 'generate_charon_logging');
ok(grep { /<subsystem> = <default>/ } generate_charon_logging() );
ok(grep { /default = -1/ } generate_charon_logging( qw( none ) ) );
ok(grep { /default = 2/ } generate_charon_logging( qw( all ) ) );
# this time we only want to see one cfg entry
my @lines = split /^/, generate_charon_logging(qw( control parsing ));
is((grep { /cfg/ } @lines), 1);
