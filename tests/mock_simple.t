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

use Test::More tests => 11;
use Test::Exception;

use_ok('Test::Vyatta::MockSimple', qw( mock_capture_retval
                                       mock_read_file_retval
                                       mock_readpipe_retval ) );

my @test_array = ( '1st line', '2nd line', '3rd line' );
my $expected_string = "1st line\n2nd line\n3rd line";
mock_capture_retval('ipsec statusall', \@test_array);
is(@{[ IPC::System::Simple::capture('ipsec statusall') ]},
   scalar @test_array, 'array test for capture');
is(IPC::System::Simple::capture('ipsec statusall'),
   $expected_string, 'string test for capture');

dies_ok { IPC::System::Simple::capture('oink') } 'dies on unknown commands';

mock_read_file_retval('/etc/ipsec.conf', \@test_array);
is(@{[ File::Slurp::read_file('/etc/ipsec.conf') ]},
   scalar @test_array, 'array test for read_file');
is(File::Slurp::read_file('/etc/ipsec.conf'),
   $expected_string, 'string test for read_file');

dies_ok { File::Slurp::read_file('oink') } 'dies on unknown file';

#
# For use_ok() we need to place an additional BEGIN here.
#
BEGIN {
    no warnings 'redefine';
    *CORE::GLOBAL::readpipe = \&Test::Vyatta::MockSimple::_readpipe;
}

@test_array = ( $$ );
my @pids = qx'echo -n $PPID';
is_deeply(\@pids, \@test_array, 'readpipe: unmocked call');

@test_array = ( 1234, 1235 );
mock_readpipe_retval('pgrep test', \@test_array);
@pids = qx(pgrep test);
is_deeply(\@pids, \@test_array, 'readpipe: array test');

dies_ok { qx(pgrep croak) } 'readpipe: dies on unknown commands';

mock_readpipe_retval('pgrep test', undef);
my $str = qx(echo -n empty);
is($str, 'empty', 'readpipe: deletes mocked command');
