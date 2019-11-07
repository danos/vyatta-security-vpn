#
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#

# SPDX-License-Identifier: GPL-2.0-only

package Test::Vyatta::MockSimple;

use strict;
use warnings 'all';

use parent qw(Exporter);
our @EXPORT_OK = qw(mock_capture_retval mock_read_file_retval
                    mock_readpipe_retval);

use File::Slurp;
use IPC::System::Simple;
use Carp qw(croak);

our $orig_capture;
my %mock_retval = ();
our $call_mocked_capture;

sub mock_capture_retval {
    my ( $cmd, $retval ) = @_;
    @{ $mock_retval{$cmd} } = @$retval;
    $call_mocked_capture = 1;
    return;
}

sub _capture {
    my $valid_returns = 0;

    if (ref $_[0] eq 'ARRAY') {
        $valid_returns = shift(@_);
    }

    my ($cmd, @args) = @_;
    my $str = join(' ', $cmd, @args);
    return orig_capture($valid_returns, $cmd, @args)
        if not $call_mocked_capture;
    croak "Unsupported arguments: $str"
        if not exists $mock_retval{$str};
    return wantarray ? @{ $mock_retval{$str} }
        : join("\n", @{ $mock_retval{$str} });
}

BEGIN {
    *orig_capture = \&IPC::System::Simple::capture;
}

BEGIN {
    package IPC::System::Simple;

    no warnings 'redefine';
    *IPC::System::Simple::capture = \&Test::Vyatta::MockSimple::_capture;
}

our $orig_read_file;
my %read_file_retval = ();
our $call_mocked_read_file;

sub mock_read_file_retval {
    my ( $file, $retval ) = @_;
    @{ $read_file_retval{$file} } = @$retval;
    $call_mocked_read_file = 1;
    return;
}

sub _read_file {
    my ($file) = @_;
    return orig_read_file($file)
        if not $call_mocked_read_file;
    croak "Unsupported arguments: $file"
        if not exists $read_file_retval{$file};
    return wantarray ? @{ $read_file_retval{$file} }
        : join("\n", @{ $read_file_retval{$file} });
}

BEGIN {
    *orig_read_file = \&File::Slurp::read_file;
}

BEGIN {
    package File::Slurp;

    no warnings 'redefine';
    *File::Slurp::read_file = \&Test::Vyatta::MockSimple::_read_file;
}

#
# Helper to simplify mocking of qx(), `` (backticks) operator and readpipe().
#

our $orig_readpipe;
my %readpipe_retval = ();

sub mock_readpipe_retval {
    my ( $file, $retval ) = @_;
    if (defined $retval) {
        @{ $readpipe_retval{$file} } = @$retval;
    } else {
        delete $readpipe_retval{$file};
    }
    return;
}

sub _readpipe {
    my ($cmd) = @_;

    # use the real readpipe
    #
    # NOTE: Be aware of a bug in qx() and `` operator with variable
    #       expansion. If required use readpipe() directly.
    return CORE::readpipe($cmd)
        if not keys %readpipe_retval;
    croak "Unsupported arguments: $cmd"
        if not exists $readpipe_retval{$cmd};
    return wantarray ? @{ $readpipe_retval{$cmd} }
        : join("\n", @{ $readpipe_retval{$cmd} });
}

BEGIN {
    no warnings 'redefine';
    *CORE::GLOBAL::readpipe = \&Test::Vyatta::MockSimple::_readpipe;
}

1;
