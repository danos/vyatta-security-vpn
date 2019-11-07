#!/usr/bin/perl -w

#
# Copyright:
#
#	Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
#	Copyright (c) 2007-2016 by Brocade Communications Systems, Inc.
#	All Rights Reserved.
#
# License:
#
# This software is licensed, and not freely distributable. See the
# license agreement for details.
#

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::VPN::Util qw(rsa_get_local_pubkey rsa_public_digest
                         vpn_debug);
use Vyatta::VPN::Config qw(rsa_get_local_key_file);
use Vyatta::Config qw(get_short_config_path);
use File::Basename;
use File::Path;
use Getopt::Long;

use constant {
	bits_min => 1024,
	bits_max => 4096,
	bits_multiple => 16,
	bits_default => 2192,
};

my $prog = basename($0);

# Defaults
my $bits = bits_default;

my $f4 = 0;

sub usage
{
    die "Usage: $prog [ --F4 ] [ <bits> ]\n";
}

GetOptions("F4" => \$f4)
  || usage();

if (@ARGV > 1) {
    usage();
} elsif (@ARGV == 1) {
    $bits = $ARGV[0];
}

if ($bits !~ m/^\d+$/) {
   die "bits must be an integer\n";
}
if ($bits > bits_max) {
    die "bits must be <= " . bits_max . "\n";
}
if ($bits < bits_min) {
    die "bits must be >= " . bits_min . "\n";
}
if ($bits % bits_multiple != 0) {
    die "bits must be a multiple of " . bits_multiple . "\n";
}

my $old_umask = umask(0027);

my $local_key_file = rsa_get_local_key_file();

my ($cmd, $rc);

if (-r $local_key_file) {
    $| =1;   # force a flush
    print "A local RSA key file already exists and will be overwritten\n";
    print "<CTRL>C to exit:  ";
    my $loop = 9;
    while ($loop) {
	print "\b$loop";
	sleep 1;
	$loop--;
    }
    print "\n";
} else {
    my $err = undef;
    my ($dirpath) = dirname($local_key_file);
    eval {
        mkpath($dirpath);
    };
    if ($@) {
        die "Cannot mkdir $dirpath $!\n";
    }
}

$cmd = "generate_new_rsasig.pl";

# use --F4 to set public exponent to 65537
$cmd .= " --F4" if ($f4);

$cmd .= " --bits $bits $local_key_file";

# when presenting to users, show shortened /config path
my $shortened_cfg_path_file = get_short_config_path($local_key_file);
print "Generating rsa-key to $shortened_cfg_path_file\n";

vpn_debug $cmd;
$rc = system($cmd);
if ($rc != 0) {
    die "Cannot generate RSA key: $!\n";
}

my $rsa_public = rsa_get_local_pubkey($local_key_file);
if (!defined($rsa_public)) {
    die "Cannot find pubkey\n";
}

my $digest = rsa_public_digest($rsa_public, \&Digest::MD5::md5);

my $formatted = join(':', (unpack('H*', $digest) =~ m/../g));

printf "\nYour new local RSA key has been generated.\n" .
"RSA key fingerprint: %s\n", $formatted;

$cmd = "ipsec rereadall 2>/dev/null";
vpn_debug $cmd;
system $cmd;

umask($old_umask);

exit 0;
