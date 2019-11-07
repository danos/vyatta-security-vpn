#!/usr/bin/perl -w

# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use File::Basename;
use Cwd 'abs_path';
use lib abs_path(dirname(__FILE__) . '/../lib');

use Test::More tests => 3;

use_ok('Vyatta::VPN::VTIIntf', qw( parseVtiTun ));

my $single_key_in  = 'vti2: ip/ip  remote 12.0.0.2  local 12.0.0.1  ttl inherit  nopmtudisc key 15';
my @single_key_out = ('12.0.0.2', '12.0.0.1', 'vti2', 15, 15);

my $two_keys_in = 'vti0: ip/ip  remote 10.22.4.5  local 10.22.4.6  ttl inherit  nopmtudisc ikey 0  okey 2415919105';
my @two_keys_out = ('10.22.4.5', '10.22.4.6', 'vti0', 0, 2415919105);

my @single_key_result = parseVtiTun( $single_key_in );
is_deeply( \@single_key_out, \@single_key_result, 'VTI parsing with a single key');

my @two_keys_result = parseVtiTun( $two_keys_in);
is_deeply( \@two_keys_out, \@two_keys_result, 'VTI parsing with different keys for input and output');
