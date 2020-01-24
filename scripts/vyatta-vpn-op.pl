#!/usr/bin/perl -w
# Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# Copyright (c) 2008-2009, 2011-2012 Vyatta, Inc.
# All rights reserved.


# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;

use File::Copy;
use File::Slurp qw( edit_file );
use Getopt::Long;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;

my $op='';
my $peer=undef;
my $tunnel=undef;
my $s2s_peer_path='security vpn ipsec site-to-site peer';

# not used on all ops, but that's okay
my $config = Vyatta::Config->new();

GetOptions( "op=s"      => \$op,
            "peer=s"    => \$peer,
            "tunnel=s"  => \$tunnel);

sub numerically { return $a <=> $b; }

sub get_tunnels {
  my $s2s_peer = undef;
  $s2s_peer = shift;
  my @peer_tunnels = ();
  if (defined $s2s_peer) {
    @peer_tunnels = $config->listOrigNodes("$s2s_peer_path $s2s_peer tunnel");
  }
  return @peer_tunnels;
}

sub get_vtis {
  my $s2s_peer = undef;
  $s2s_peer = shift;
  my @peer_tunnels = ();
  if (defined $s2s_peer) {
    @peer_tunnels = $config->listOrigNodes("$s2s_peer_path $s2s_peer vti");
  }
  return @peer_tunnels;
}

sub clear_tunnel {
  my ($peer, $tunnel, $childSA) = @_;
  my $conn = "peer-$peer-tunnel-$tunnel";
 
  $tunnel .= "{*}" if $childSA;
  print "Resetting tunnel $tunnel with peer $peer...\n";

  # Queue terminate/initiate in charon job queues with non-blocking stroke calls.
  # charon/control schedules both with the same priority (medium).
  my $suffix = $childSA ? "{*}" : "";
  `ipsec stroke down-nb '$conn$suffix' >&/dev/null`;
  `ipsec stroke up-nb '$conn' >&/dev/null`;

  return;
}

if ($op eq '') {
  die 'No op specified';
}

if ($op eq 'clear-vpn-ipsec-process') {
  print "Restarting IPsec process...\n";
  system 'systemctl restart strongswan.service';

  if (is_opennhrp_running()) {
	system 'systemctl restart opennhrp.service';
  }
  
} elsif ($op eq 'show-vpn-debug') {
	system '/usr/sbin/ipsec statusall';

} elsif ($op eq 'show-vpn-debug-detail') {
	system '/opt/vyatta/bin/vyatta-show-vpn-debug.sh';

} elsif ($op eq 'get-all-peers') {
  # get all site-to-site peers
  my @peers = $config->listOrigNodes($s2s_peer_path);
  print join(' ', @peers), "\n";

} elsif ($op eq 'get-tunnels-for-peer') {
  # get all tunnels for a specific site-to-site peer
  die 'Undefined peer to get list of tunnels for' unless defined $peer;
  my @peer_tunnels = get_tunnels($peer);
  print join(' ', @peer_tunnels), "\n";

} elsif ($op eq 'clear-tunnels-for-peer') {
  # clear all tunnels for a given site-to-site peer
  die 'Undefined peer to clear tunnels for' unless defined $peer;
  my @peer_tunnels = get_tunnels($peer);
  if (scalar(@peer_tunnels) > 0) {
    foreach my $tun (sort numerically @peer_tunnels) {
      clear_tunnel($peer, $tun);
    }
  } else {
    my @peer_vtis = get_vtis($peer);
    if (scalar(@peer_vtis) == 0) {
        die "No tunnel defined for peer $peer\n";
    }
    clear_tunnel($peer, 'vti');
  }

} elsif ($op eq 'clear-specific-tunnel-for-peer') {
  # clear a specific tunnel for a given site-to-site peer
  die 'Undefined peer to clear tunnel for' unless defined $peer;
  die 'Undefined tunnel for peer $peer' unless defined $tunnel;
  my @peer_tunnels = get_tunnels($peer);
  if (scalar(grep { /^$tunnel$/ } @peer_tunnels) == 0) {
    die "Undefined tunnel $tunnel for peer $peer\n";
  }
  clear_tunnel($peer, $tunnel, 1);

} elsif ($op eq 'clear-vtis-for-peer') {
  # clear all vti for a given site-to-site peer
  die 'Undefined peer to clear vti for' unless defined $peer;
  my @peer_vtis = get_vtis($peer);
  if (scalar(@peer_vtis) == 0) {
    die "No vti defined for peer $peer\n";
  }
  clear_tunnel($peer, 'vti');

} else { 
  die "Unknown op: $op";
}
 
sub is_opennhrp_running {
  return (qx(pgrep opennhrp) ne "");
}

exit 0;
