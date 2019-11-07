#!/usr/bin/perl -w
#
# Copyright:
#
#   Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
#   Copyright (c) 2014-2017 by Brocade Communications Systems, Inc.
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

use Crypt::OpenSSL::RSA;
use File::Slurp;
use File::Basename;
use Sys::Hostname;

my $prog = basename($0);

# trim domain portion?
(my $hostname = hostname()) =~ s/\..*$//;

die "usage: $prog infile outfile\n"
    unless (@ARGV == 2);

my $infile = shift;
my $outfile = shift;

my $key = read_file($infile, err_mode => 'quiet');

die "Cannot read $infile\n"
    unless ($key);

my $priv = Crypt::OpenSSL::RSA->new_private_key($key);

open(my $out, '>', $outfile)
  || die "Cannot write to $outfile\n";

my $timestamp = (stat($infile))[9];

print $out as_rsa_key($priv, $hostname, $timestamp);

close($out);

# our modification timestamp should match that of our source key file
utime(0, $timestamp, $outfile)
  || warn "Cannot reset modified time\n";

