#!/usr/bin/perl -w

#
# Copyright:
#
#   Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
#   Copyright (c) 2014 by Brocade Communications Systems, Inc.
#   All Rights Reserved.
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
use Vyatta::VPN::Util qw(as_raw_key);
use Crypt::OpenSSL::RSA;
use File::Basename;
use Sys::Hostname;
use Getopt::Long;

use constant {
	bits_min => 1024,
	bits_max => 4096,
	bits_multiple => 16,
};

my $prog = basename($0);

# trim domain portion?
(my $hostname = hostname()) =~ s/\..*$//;

my $bits = 0;
my $f4 = 0;

GetOptions("bits=i" => \$bits,
	   "F4" => \$f4)
  || die "usage: $prog [--F4] --bits nnn outfile\n";

my $exp = $f4 ? 65537 : 3;

die "usage: $prog [--F4] --bits nnn outfile\n"
    unless (@ARGV == 1);

my $outfile = shift;

die "error: bits must be " . bits_min . "-" . bits_max . " and multiple of " . bits_multiple . "\n"
    unless ($bits =~ m/^\d+$/ && $bits >= bits_min && $bits <= bits_max && $bits % bits_multiple == 0);

my $priv = Crypt::OpenSSL::RSA->generate_key($bits, $exp);

open(my $out, '>', $outfile)
  || die "Cannot write to $outfile\n";

print $out $priv->get_private_key_string();

close($out);

