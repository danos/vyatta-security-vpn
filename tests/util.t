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

use MIME::Base64;
use Test::More 'no_plan';  # or use Test::More 'no_plan';
use Test::Exception;

use Test::MockObject;
my $mock = Test::MockObject->new();
$mock->fake_module( 'Vyatta::Config' );

use_ok('Vyatta::VPN::Util', qw(:ALL) );

use lib dirname(__FILE__);
use TestData_Util;

use Test::Vyatta::MockSimple qw(mock_read_file_retval mock_readpipe_retval);

SKIP: {
    skip '/var/run/pluto.pid file detected', 1 if -e '/var/run/pluto.pid';

    # daemon not running and not mocked
    is(get_daemon_pid(), undef);
}

my @test_pid = ( );
mock_readpipe_retval('cat /var/run/charon.pid 2>/dev/null', \@test_pid);
mock_readpipe_retval('pgrep charon 2>/dev/null', \@test_pid);
# daemon not running
is(get_daemon_pid(), undef);

# daemon running
@test_pid = ( 1234 );
mock_readpipe_retval('cat /var/run/charon.pid 2>/dev/null', \@test_pid);
mock_readpipe_retval('pgrep charon 2>/dev/null', \@test_pid);
is(get_daemon_pid(), 1234);

my @expected_array = ( 'modp1536', 'modp1024' );
my @array = uniq(@expected_array, @expected_array);
is_deeply(\@array, \@expected_array, 'uniq 1');
@expected_array = ( 'modp1536', 'modp1024', 'modp2048' );
@array = uniq('modp1536', 'modp1024', 'modp1024', 'modp1536', 'modp2048');
is_deeply(\@array, \@expected_array, 'uniq 2');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_raw);
my $type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "RAW", 'get_pki_key_type: RAW');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_pem_pkcs1);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "RSA", 'get_pki_key_type: RSA Private PKCS#1');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@public_pem_pkcs1);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "RSA", 'get_pki_key_type: RSA Public PKCS#1');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_pem_pkcs8);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "RSA", 'get_pki_key_type: RSA Private PKCS#8');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@public_pem_pkcs8);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "RSA", 'get_pki_key_type: RSA Public PKCS#8');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@ec_private_pem_sec1);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "ECDSA", 'get_pki_key_type: ECDSA Private SEC 1');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@ec_private_pem_pkcs8);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "ECDSA", 'get_pki_key_type: ECDSA Private PKCS#8');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@ec_public_pem_pkcs8);
$type = get_pki_key_type('/config/ipsec.d/rsa-keys/localhost.key');
is( $type, "ECDSA", 'get_pki_key_type: ECDSA Public PKCS#8');

my $rsa = rfc2537_to_rsa_pubkey($dnssec_rfc2537);
my ($n, $e) = $rsa->get_key_parameters();
is(encode_base64($n->to_bin, ''), $dnssec_private{Modulus},
   'rfc2537_to_rsa_pubkey: Modulus');
is(encode_base64($e->to_bin, ''), $dnssec_private{PublicExponent},
   'rfc2537_to_rsa_pubkey: PublicExponent');

$rsa = Crypt::OpenSSL::RSA->new_public_key(join("\n", @public_pem_pkcs1));
my $rsa_rfc2537 = rsa_pubkey_to_rfc2537($rsa);
is ( $rsa_rfc2537, $public_rfc2537, 'RSA pubkey to RFC 2537' );

$rsa = rfc2537_to_rsa_pubkey($public_rfc2537);
is( $rsa->get_public_key_string(), join("\n", @public_pem_pkcs1) . "\n",
    'RFC 2537 to PKCS#1');
is( $rsa->get_public_key_x509_string(), join("\n", @public_pem_pkcs8) . "\n",
    'RFC 2537 to PKCS#8');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_raw);
$rsa = rsa_get_local_pubkey('/config/ipsec.d/rsa-keys/localhost.key');
is( $rsa->get_public_key_string(), join("\n", @public_pem_pkcs1) . "\n",
    'RAW to PKCS#1');
is( $rsa->get_public_key_x509_string(), join("\n", @public_pem_pkcs8) . "\n",
    'RAW to PKCS#8');

my $digest = rsa_public_digest($rsa, \&Digest::MD5::md5);
my $formatted = join(':', (unpack('H*', $digest) =~ m/../g));
is($formatted, '2b:36:71:4b:c3:c5:66:03:4b:e0:fd:6a:9b:fd:ba:8c',
   'RSA pubkey fingerprint (MD5)');

$rsa = rfc2537_to_rsa_pubkey($large_exp_rfc2537);
$digest = rsa_public_digest($rsa, \&Digest::MD5::md5);
$formatted = join(':', (unpack('H*', $digest) =~ m/../g));
is($formatted, 'ca:11:44:68:a3:38:bb:29:3f:07:90:ef:3c:73:b0:6f',
   'Large exponent RSA pubkey fingerprint (MD5)');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_pem_pkcs1);
$rsa = rsa_get_local_pubkey('/config/ipsec.d/rsa-keys/localhost.key');
is( $rsa->get_public_key_string(), join("\n", @public_pem_pkcs1) . "\n",
    'PKCS#1 to RSA pubkey');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_pem_pkcs8);
$rsa = rsa_get_local_pubkey('/config/ipsec.d/rsa-keys/localhost.key');
is( $rsa->get_public_key_string(), join("\n", @public_pem_pkcs1) . "\n",
    'PKCS#8 to RSA pubkey');

mock_read_file_retval('/config/ipsec.d/rsa-keys/localhost.key',
                      \@private_raw);
$rsa = rsa_key_from_raw_key('/config/ipsec.d/rsa-keys/localhost.key');
is( $rsa->get_private_key_string(), join("\n", @private_pem_pkcs1) . "\n",
    'rsa_key_from_raw_key: private PKCS#1');
is( $rsa->get_public_key_string(), join("\n", @public_pem_pkcs1) . "\n",
    'rsa_key_from_raw_key: public PKCS#1');
is( $rsa->get_public_key_x509_string(), join("\n", @public_pem_pkcs8) . "\n",
    'rsa_key_from_raw_key: public PKCS#8');

# conv_proto_port
is(conv_proto_port('[1024]'), ('all', '1024'), 'conv_proto_port: port integer');
is(conv_proto_port('[tcp/1024]'), ('tcp', '1024'), 'conv_proto_port: protocol/port tuple');
is(conv_proto_port('[gre]'), ('gre', 'all'), 'conv_proto_port: protocol string');
is(conv_proto_port(''), ('all', 'all'), 'conv_proto_port: empty string');
is(conv_proto_port(undef), ('all', 'all'), 'conv_proto_port: undef string');
dies_ok { conv_proto_port('[47/47]') } 'conv_proto_port: protocol needs to pass Vyatta::TypeChecker validate_protocol';
is(conv_proto_port('[tcp/ssh]'), ('tcp', 'ssh'), 'conv_proto_port: port as well-known string');

# conv_intf
is(conv_intf('dp0s3'), 'dp0s3', 'conv_intf: dp0s3');
is(conv_intf('dp0bond0'), 'dp0bond0', 'conv_intf: dp0bond0');
is(conv_intf('dp0bond0.2000@dp0bond0'), 'dp0bond0.2000', 'conv_intf: dp0bond0.20000@dp0bond0');
is(conv_intf('dp0vrrp1@dp0bond1'), 'dp0vrrp1', 'conv_intf: dp0vrrp1@dpbond1');

#tests for tnormal function
my $atime = tnormal(5, "minutes");
is( $atime, 300);
$atime = tnormal(5, "hours");
is( $atime, 18000);
$atime = tnormal(1, "days");
is( $atime, 86400);
