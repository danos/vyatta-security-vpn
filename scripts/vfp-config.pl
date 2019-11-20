#!/usr/bin/perl
#
# Copyright (c) 2017-2019 AT&T Intellectual Property.
# All rights reserved.
#

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;
use Vyatta::VPN::Constants qw( VFP_STATE_DIR );
use File::Slurp qw( write_file read_dir);

my $ipsec_s2s_cli = 'security vpn ipsec site-to-site peer';
my $ipsec_s2s_prefix = 'peer';
my $ipsec_ra_vpn_client_cli = 'security vpn ipsec remote-access-client profile';
my $ipsec_ra_vpn_server_cli = 'security vpn ipsec remote-access-server profile';
my $ipsec_ra_vpn_client_prefix = 'ipsec_ra_client';
my $ipsec_ra_vpn_server_prefix = 'ipsec-remote-access-server';
my $config = Vyatta::Config->new();
my $psuf = '.prev';


sub write_vfp_state {
    my ($connection, $ifname) = @_;
    my $fn = VFP_STATE_DIR . $connection;
    write_file($fn, $ifname);
    unlink $fn . $psuf if ( -f $fn . $psuf );
}

sub read_vfp_conf {
    my ($cli, $prefix) = @_;

    $config->setLevel($cli);
    my @peers = $config->listNodes();
    foreach my $peer (@peers) {

        my @tunnels = $config->listNodes("$peer tunnel");
        foreach my $tunnel (@tunnels) {


            next if $config->exists("$peer tunnel $tunnel disable");


            my $ifname = $config->returnValue("$peer tunnel $tunnel uses");
            next if !defined($ifname);

            # IPsec RA VPN client:
            #    ipsec_ra_client-$(profile)-$(server_ip)-tunnel-$(X)
            # IPsec site-to-site :
            #    peer-$(peer_ip)-tunnel-$(X)
            #
            # Remove .prev file for any new conf file we create.

            if ( $prefix eq $ipsec_ra_vpn_client_prefix ) {
                my @servers = $config->listNodes("$peer server");
                foreach my $server (@servers) {
                    if ($config->exists("$peer server $server source-interface")) {
                        my @source_intfs = $config->listNodes("$peer server $server source-interface");
                        foreach my $source_intf (@source_intfs) {
                            my $connection = $prefix .'-'. $peer .'-'. $source_intf .'-'. $server .'-tunnel-' . $tunnel;
                            write_vfp_state($connection, $ifname);
                        }
                    } else {
                        my $connection = $prefix .'-'. $peer .'-'. $server .'-tunnel-' . $tunnel;
                        write_vfp_state($connection, $ifname);
                    }
                }
            } else { # ra_vpn_server and s2s
                my $connection = $prefix .'-'. $peer . '-tunnel-' . $tunnel;
                write_vfp_state($connection, $ifname);
            }
        }
    }
}

#
# Rename exising entries to *.prev to enable us to send the final
# "detach" if the vfp is being unbound.
#
sub flush_vfp_state {
    my @files = read_dir(VFP_STATE_DIR, prefix => 1);
    foreach my $fn (@files) {
	if (! ( $fn =~ /prev$/ )) {
           rename $fn, $fn . ".prev" if (-f $fn);
	}
    }
}

flush_vfp_state();
read_vfp_conf($ipsec_s2s_cli, $ipsec_s2s_prefix);
read_vfp_conf($ipsec_ra_vpn_client_cli, $ipsec_ra_vpn_client_prefix);
read_vfp_conf($ipsec_ra_vpn_server_cli, $ipsec_ra_vpn_server_prefix);

exit 0;
