#!/usr/bin/perl -w
#
# Module: vyatta_show_vpn.pl
# 
# **** License ****
# 
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
# 
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
# 
# Description: Utility to show various vpn values
# 
# **** End License ****
# 

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5";

my $arg0 = $ARGV[0];
if (!defined($arg0)) {
    die "Please specify either 'secrets' or 'rsa-keys'.\n";
}

if ($arg0 eq 'secrets') {
    my $secret_file = '/etc/ipsec.secrets';
    unless ( -r $secret_file) {
	die "No secrets file $secret_file\n";
    }
    open(my $DAT, '<', $secret_file);
    my @raw_data=<$DAT>;
    close($DAT);
    print "Local           Peer            Local ID      Peer ID       Secret\n";
    print "--------        -------         --------      -------       ------\n";
    foreach my $line (@raw_data) {
	    if ($line =~ /PSK/) {
	      my ($lip, $pip, $lid, $pid, $secret) = ('', '', 'N/A', 'N/A', '');
	      ($secret) = $line =~ /.*:\s+PSK\s+(\"\S+\")/;
	      ($lip, $pip) = $line =~ /^(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/;
        # This processing with depend heavily on the way we write ipsec.secrets
        # lines with 3 entries are tagged by the config module so that we can tell
        # if the 3rd entry is a localid or peerid (left or right)
        if (! defined($lip)){
          if ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/){
            $lip = $1;
            $pip = $2;
            $lid = $3;
            $pid = $4;
          } elsif ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\".*\#(.*)\#/){
            $lip = $1;
            $pip = $2;
            if ($4 eq 'RIGHT'){
              $pid = $3
            } else {$lid = $3}
          }
        }
	      $lip = '0.0.0.0' if ! defined $lip;
	      $pip = '0.0.0.0' if ! defined $pip;
	      printf "%-15s %-15s %-13s %-13s %s\n", $lip, $pip, substr($lid,0,12), substr($pid,0,12), $secret;
	    }
    }
    exit 0;
}

if ($arg0 eq 'rsa-keys') {
    use Vyatta::VPN::Util qw(rsa_get_local_pubkey rsa_pubkey_to_rfc2537);
    use Vyatta::VPN::Config qw(rsa_get_local_key_file);
    my $key_file = rsa_get_local_key_file();
    unless ( -r $key_file) {
        die "No key file $key_file found.\n";
    }
    my $pubkey = rsa_get_local_pubkey($key_file);
    if (!defined($pubkey)) {
	die "No local pubkey found.\n";
    }
    print "\nLocal public key ($key_file):\n\n" .
        rsa_pubkey_to_rfc2537($pubkey) . "\n\n";

    use Vyatta::Config;
    my $vc = Vyatta::Config->new();
    $vc->setLevel('security vpn');

    my @peers = $vc->listOrigNodes('ipsec site-to-site peer');
    foreach my $peer (@peers) {
        my $mode = $vc->returnOrigValue("ipsec site-to-site peer $peer authentication mode");
        if ($mode eq 'rsa') {
            my $rsa_key_name = $vc->returnOrigValue("ipsec site-to-site peer $peer authentication rsa-key-name");
            my $remote_key = $vc->returnOrigValue("rsa-keys rsa-key-name $rsa_key_name rsa-key");
            print "=" x 80, "\n";
            print "Peer: $peer";
            if (defined($rsa_key_name)) {
                print "  ($rsa_key_name)";
            }
            print "\n\n";
            if (defined($remote_key)) {
                print "$remote_key\n";
            }
        }
    }
}

