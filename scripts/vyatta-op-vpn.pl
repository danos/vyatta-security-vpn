#!/usr/bin/perl
#
# Module: vyatta-op-vpn.pl
#
# **** License ****
# Copyright (c) 2019 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2008-2013 Vyatta, Inc.
# All Rights Reserved.
#
# Description: Script to execute op-mode commands for IPSEC VPN
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;

use Getopt::Long;
use lib "/opt/vyatta/share/perl5";
use Vyatta::VPN::OPMode qw(:cli :ipsec :ike);
use Vyatta::VPN::Util qw(get_daemon_pid);

my ($get_peers_for_cli, $get_conn_for_cli, $show_ipsec_sa, $show_ipsec_sa_detail,
    $show_ipsec_sa_peer, $show_ipsec_sa_peer_detail, $show_ipsec_sa_natt, 
    $show_ipsec_sa_stats, $show_ipsec_sa_stats_peer, $show_ike_sa, 
    $show_ike_sa_peer, $show_ike_sa_natt, $show_ike_secrets, $show_ike_status,
    $show_ipsec_status, $get_profiles_for_cli, $show_ipsec_sa_profile,
    $show_ipsec_sa_profile_detail, $show_ipsec_sa_stats_profile);
my @show_ipsec_sa_stats_conn;
my @show_ipsec_sa_conn_detail;
my @show_ipsec_sa_conn;

GetOptions("show-ipsec-sa!"                 => \$show_ipsec_sa,
           "show-ipsec-sa-detail!"          => \$show_ipsec_sa_detail,
           "get-peers-for-cli!"             => \$get_peers_for_cli,
           "get-profiles-for-cli!"          => \$get_profiles_for_cli,
           "get-conn-for-cli=s"             => \$get_conn_for_cli,
           "show-ipsec-sa-peer=s"           => \$show_ipsec_sa_peer,
           "show-ipsec-sa-peer-detail=s"    => \$show_ipsec_sa_peer_detail,
           "show-ipsec-sa-natt!"            => \$show_ipsec_sa_natt,
           "show-ipsec-sa-stats!"           => \$show_ipsec_sa_stats,
           "show-ipsec-sa-stats-peer=s"     => \$show_ipsec_sa_stats_peer,
           "show-ipsec-sa-stats-conn=s{2}"  => \@show_ipsec_sa_stats_conn,
           "show-ipsec-sa-profile=s"        => \$show_ipsec_sa_profile,
           "show-ipsec-sa-profile-detail=s" => \$show_ipsec_sa_profile_detail,
           "show-ipsec-sa-stats-profile=s"  => \$show_ipsec_sa_stats_profile,
           "show-ipsec-sa-conn-detail=s{2}" => \@show_ipsec_sa_conn_detail,
           "show-ipsec-sa-conn=s{2}"        => \@show_ipsec_sa_conn,
           "show-ipsec-status!"             => \$show_ipsec_status,
           "show-ike-sa!"                   => \$show_ike_sa,
           "show-ike-sa-peer=s"             => \$show_ike_sa_peer,
           "show-ike-sa-natt!"              => \$show_ike_sa_natt,
           "show-ike-status!"               => \$show_ike_status,
           "show-ike-secrets!"              => \$show_ike_secrets);

if (!defined(get_daemon_pid())) {
  print STDERR "IPsec Process NOT Running\n";
  exit 1;
}
if (defined $get_peers_for_cli) {
  get_peers_for_cli();
}
if (defined $get_profiles_for_cli) {
  get_profiles_for_cli();
}
if (defined $get_conn_for_cli) {
  get_conn_for_cli($get_conn_for_cli);
}
if (defined $show_ipsec_sa) {
  show_ipsec_sa();
}
if (defined $show_ipsec_sa_detail) {
  show_ipsec_sa_detail();
}
if (defined $show_ipsec_sa_peer) {
  show_ipsec_sa_peer($show_ipsec_sa_peer);
}
if (defined $show_ipsec_sa_peer_detail) {
  show_ipsec_sa_peer_detail($show_ipsec_sa_peer_detail);
}
if (defined $show_ipsec_sa_profile) {
  show_ipsec_sa_profile($show_ipsec_sa_profile);
}
if (defined $show_ipsec_sa_profile_detail) {
  show_ipsec_sa_profile_detail($show_ipsec_sa_profile_detail);
}
if (@show_ipsec_sa_conn_detail) {
  show_ipsec_sa_conn_detail(@show_ipsec_sa_conn_detail);
}
if (@show_ipsec_sa_conn) {
  show_ipsec_sa_conn(@show_ipsec_sa_conn);
}
if (defined $show_ipsec_sa_natt) {
  show_ipsec_sa_natt();
}
if (defined $show_ipsec_sa_stats) {
  show_ipsec_sa_stats();
}
if (defined $show_ipsec_sa_stats_peer) {
  show_ipsec_sa_stats_peer($show_ipsec_sa_stats_peer);
}
if (@show_ipsec_sa_stats_conn) {
  show_ipsec_sa_stats_conn(@show_ipsec_sa_stats_conn);
}
if (defined $show_ipsec_sa_stats_profile) {
  show_ipsec_sa_stats_profile($show_ipsec_sa_stats_profile);
}
if (defined $show_ipsec_status) {
  show_ipsec_status();
}
if (defined $show_ike_sa) {
  show_ike_sa();
}
if (defined $show_ike_status) {
  show_ike_status();
}
if (defined $show_ike_sa_peer) {
  show_ike_sa_peer($show_ike_sa_peer);
}
if (defined $show_ike_sa_natt) {
  show_ike_sa_natt();
}
if (defined $show_ike_secrets) {
  show_ike_secrets();
}
