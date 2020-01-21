#!/usr/bin/perl
#
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2016 by Brocade Communications Systems, Inc.
# All rights reserved.

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;

sub get_deleted_peers {
    my @dead_peers;
    my $config = Vyatta::Config->new("security vpn ipsec site-to-site");

    foreach my $peer ($config->listNodes("peer"),
                      $config->listDeleted("peer")) {
        foreach my $id ($config->listDeleted("peer $peer tunnel")) {
            push(@dead_peers, "peer-$peer-tunnel-$id");
        }
        foreach my $id ($config->listNodes("peer $peer tunnel")) {
            next unless $config->isAdded("peer $peer tunnel $id disable");
            push(@dead_peers, "peer-$peer-tunnel-$id");
        }
        foreach my $vti ($config->listDeleted("peer $peer vti")) {
            push(@dead_peers, "peer-$peer-tunnel-vti");
        }
    }

    return @dead_peers;
}

foreach my $peer (get_deleted_peers()) {
    system("ipsec stroke down-nb '$peer' >/dev/null 2>&1");
}
