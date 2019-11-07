#!/usr/bin/perl -w
#
# Module: vyatta-vti-config.pl
#
# **** License ****
# Copyright (c) 2017, 2019 AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2014-2017 Brocade Communications Systems, Inc.
# All Rights Reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
#
# Description: setup the vti tunnel
#
# **** End License ****
#
# SPDX-License-Identifier: GPL-2.0-only
#
# For each VTI tunnel (vpn ipsec site-to-site peer ip-address sti); find the vti tunnel, local address, mark.
#   Find the corresponding tunnel (interfaces vti vtiXXX), tunnel address, disable, mtu, multicast
#        if not configured: ip tunnel add vtiXXX mode esp local $local remote $remote i_key $mark
#                           if (mtu): configure mtu
#                           if (multicast disable): unconfigure multicast
#                           if (tunnel-addres): configur ip link vtiXXX address
#                           if (!disable): enable the interface.
#

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";

use Env qw(vyatta_sbindir);
use Getopt::Long;
use File::Temp;
use NetAddr::IP;
use Vyatta::Configd;
use Vyatta::VPN::VTIIntf qw( allocVtiMark deleteVtibyname deleteVtinamepresent
                             discoverVtiIntfs extractRemoteLocal freeVtiMark
                             getVtibyNames getVtiNames isVtimarkpresent
                             isVtinamepresent );

my $vti_cfg_err = "VPN VTI configuration error:";
my $gencmds = "";
my $result = 0;
my $updown="";
my $intfName="";
my $action="";
my $checkref="";
my $tempdir="/var/lib/vyatta-security-vpn/vti/";

GetOptions(
    "updown" => \$updown,
    "intf=s"   => \$intfName,
    "action=s" => \$action,
    "checkref" => \$checkref,
);


#
# --updown intfName --action=[up|down]
#
if ($updown ne '') {
    if (!(defined $intfName) || $intfName eq '' ) {
        # invalid
        exit -1;
    }
    if (!(defined $action) || $action eq '' ) {
        # invalid
        exit -1;
    }
    vti_handle_updown($intfName, $action);
    exit 0;
}

#
# --checkref --intf=<intfName>
# Return 1 if the interface reference exits.
#
if ($checkref ne '' ) {
    if (!(defined $intfName) || $intfName eq '' ) {
        # invalid
        exit -1;
    }
    my $rval = vti_check_reference($intfName);
    exit $rval;
}

###
# Following code is to configure the vti.
#

discoverVtiIntfs();

#
# Prepare Vyatta::Config object
#
use Vyatta::Config;
my $vcIntf = Vyatta::Config->new();
my $vcVPN  = Vyatta::Config->new();
$vcVPN->setLevel('security vpn');
$vcIntf->setLevel('interfaces');

if (!$vcVPN->exists('ipsec') ) {
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}
if (!$vcVPN->exists('ipsec site-to-site') ) {
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}

    my %binds = ();
    my %vtiVpns = ();
    my @peers = $vcVPN->listNodes('ipsec site-to-site peer');
    foreach my $peer (@peers) {
        if (! $vcVPN->exists("ipsec site-to-site peer $peer vti")) {
            next;
        }
        #
        # we have the vti configured.
        #
        my $mark;
        my $lip = $vcVPN->returnValue("ipsec site-to-site peer $peer local-address");
        my $tunName = $vcVPN->returnValue("ipsec site-to-site peer $peer vti bind");
        my $change = 0;

        # Check local address is valid.
        if (!defined($lip)) {
            print STDERR "$vti_cfg_err local-address not defined.\n";
            exit -1;
        }

        if ($lip eq "" || $lip eq "0.0.0.0") {
            print STDERR "$vti_cfg_err Invalid local-address \"$lip\".\n";
            exit -1;
        }
        # Check tunName is valid.
        if (!defined($tunName) || $tunName eq ""  || ! $vcIntf->exists("vti $tunName") ) {
	    if (defined($tunName)) {
	            vti_die(["security", "vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
			    "Invalid tunnel name vti \"$tunName\".\n");
	    } else {
	            vti_die(["security", "vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
			    "tunnel name is empty.\n");
	    }
        }
        $vtiVpns{ $tunName } = 1;

        if (exists $binds{ $tunName }) {
                vti_die(["security", "vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
                    "vti bind $tunName already used.\n");
        } else {
            $binds{ $tunName } = 1;
        }

        $gencmds .= "# For peer $peer local $lip, $tunName.\n";
        #
        # Get the tunnel parameters.
        #
        # ip address's
        my @tunIPs = $vcIntf->returnValues("vti $tunName address");
        # mtu
        my $mtu = $vcIntf->returnValue("vti $tunName mtu");
        if (!defined($mtu) || $mtu eq "") {
            $mtu = 1428;
        }
        # multicast
        my $mc = $vcIntf->returnValue("vti $tunName multicast");
        my $mc_conf = "multicast on";
        if (defined($mc) && $mc eq "disable") {
          $mc_conf = "multicast off";
        }
        #my $exists = `ls -l /sys/class/net/$tunName &> /dev/null`;

        # description.
        my $description = $vcIntf->returnValue("vti $tunName description");

        # Check if the tunnel exists already: by tunnel addresses.
        my $vtiPresent = isVtinamepresent($peer, $lip);
        if (defined($vtiPresent) && !($vtiPresent eq "")) {
            if ($vtiPresent ne $tunName) {
                # Binding changed.
		my $currMark = isVtimarkpresent($peer, $lip);
		$gencmds .= "/sbin/ip link delete $vtiPresent &> /dev/null\n";
		deleteVtibyname($vtiPresent);
                $change = 1;
            }
        }

        my $existingMark = isVtimarkpresent($peer, $lip);
        if (defined($existingMark) && !($existingMark eq "")) {
	    $mark = $existingMark;
        } else {
	    $mark = allocVtiMark();
	    if ($mark == 0) {
                vti_die(["security", "vpn","ipsec","site-to-site","peer",$peer,"vti"],
                    "vti failed to create (not able to allocate a mark)\n");
	    }
            $change = 1;
        }

        deleteVtinamepresent($peer, $lip);
	deleteVtibyname($tunName);
        if ($change eq 0) {
            next;
        }

        #
        # Set the configuration into the output string.
        # Note that ipv6 tunnel does not support nopmtudisc option
        #
        # By default we delete the tunnel...
	my $genmark = $mark;
	$gencmds .= "/sbin/ip link delete $tunName &> /dev/null\n";
	if ( NetAddr::IP->new($peer)->version() == 4 ) {
	    $gencmds .= "/sbin/ip tunnel add $tunName mode vti remote $peer local $lip key $genmark nopmtudisc\n";
	    foreach my $tunIP (@tunIPs) {
		$gencmds .= "/sbin/ip addr add $tunIP dev $tunName\n";
	    }
	} else {
	    $gencmds .= "/sbin/ip -6 tunnel add $tunName mode vti6 remote $peer local $lip key $genmark\n";
	    foreach my $tunIP (@tunIPs) {
		$gencmds .= "/sbin/ip -6 addr add $tunIP dev $tunName\n";
	    }
	}

	if (-X "$vyatta_sbindir/vrf-bind-interface") {
	    $gencmds .= "$vyatta_sbindir/vrf-bind-interface --dev $tunName\n";
	}

        $gencmds .= "/sbin/ip link set $tunName mtu $mtu\n";

	#Feature toggle check - ensures feature works only on intended branches 
        if (-f '/opt/vyatta/etc/features/vyatta-security-vpn-ipsec-v1/vti-multicast-enable') {
            $gencmds .= "/sbin/ip link set $tunName $mc_conf\n";
        }

        if (defined($description)) {
            $gencmds .= "if [ -d /sys/class/net/$tunName ] ; then\n\techo \"$description\" > /sys/class/net/$tunName/ifalias\nfi\n";
        }
    }

    cleanupVtiNotConfigured();
    checkUnrefIntfVti($vcIntf, %vtiVpns);
    $result = execGenCmds();
    exit $result;

#
# get peer address for specified interface
#
sub vti_get_peer {
    my ($vtif) = @_;
    my $client = Vyatta::Configd::Client->new();
    my $cfg = 'security vpn ipsec site-to-site peer';
    my @peers = $client->get("$cfg");
    my $vtipeer = 0;

    foreach my $peer (@peers) {
        my @vti = $client->get("$cfg $peer vti bind");
        if (defined($vti[0]) && ($vti[0] eq $vtif)) {
            $vtipeer = $peer;
            last;
        }
    }
    return $vtipeer;
}

#
# Handle VTI tunnel state based on input from strongswan and configuration.
#
sub vti_handle_updown {
    my ($intfName, $action) = @_;

    use Vyatta::Config;
    my $vcIntf = Vyatta::Config->new();
    $vcIntf->setLevel('interfaces');
    my $disabled = $vcIntf->existsOrig("vti $intfName disable");
    if (!defined($disabled) || ! $disabled) {
        system("/sbin/ip link set $intfName $action\n");
    }

    my $af = 4;
    my $peer = vti_get_peer($intfName);
    if ($peer) {
	my $ipaddr = NetAddr::IP->new($peer);
	$af = $ipaddr->version;
    }

    my $iptables = "OUTPUT --table mangle --jump BYPASS";
    $iptables .= " --out-interface $intfName --iif $intfName";
    $iptables .= " --source 0/0 --destination 0/0";

    my $act;

    $iptables .= " --oif .spathintf";
    if ($action eq 'up') {
         $act = "--append";
    } else {
         $act = "--delete";
    }

    my $cmd = ($af == 4) ? "iptables" : "ip6tables";
    $cmd .= " $act $iptables";

    my $out = `$cmd 2>&1 1>/dev/null`;
    if ($?) {
        print STDERR "bind iptables: $cmd failed: $out\n";
    }
    return;
}

sub vti_check_reference {
    my ($intfName) = @_;
    use Vyatta::Config;
    my $vcVPN = Vyatta::Config->new();
    $vcVPN->setLevel('security vpn ipsec site-to-site');
    my @peers = $vcVPN->listNodes('peer');
    if (@peers == 0) {
        return 0;
    }
    foreach my $peer (@peers) {
        if (! $vcVPN->exists("peer $peer vti")) {
            next;
        }
        if ( $vcVPN->exists("peer $peer vti bind $intfName")) {
            return 1;
        }
    }
    return 0;
}

sub cleanupVtiNotConfigured {
    # for all remaining entries in the Vtinamepresent hash
    # remove them from the system.
    my $localVtiNames = getVtiNames();
    my $localVtibyNames = getVtibyNames();
    while (my ($tunKey, $presentVtiName) =  each(%$localVtiNames) ) {
        my ($remote, $local) = extractRemoteLocal($tunKey);
        my $existingMark = isVtimarkpresent($remote, $local);
        $gencmds .= "# For peer $remote local $local.\n";
        freeVtiMark($existingMark);
    }
    for my $name (keys %$localVtibyNames) {
	$gencmds .= "#For tunnel name $name.\n";
        $gencmds .= "/sbin/ip link delete $name &> /dev/null\n";
    }

    return;
}

sub execGenCmds {
    if ($gencmds ne "") {
        mkdir $tempdir unless -d $tempdir;
        my $output_config = File::Temp->new( DIR => $tempdir );
        my $fname = $output_config->filename;
        # When the file handle is closed the file will be deleted
        # unless we set unlink_on_destroy to 0. Must clean up the
        # file afterwards manually
        $output_config->unlink_on_destroy( 0 );
        print ${output_config} "#!/bin/sh\n";
        print ${output_config} $gencmds;
        close $output_config;
        chmod 0755, $fname;
        system($fname);
        $result = $? >> 8;
        unlink $fname;
        File::Temp::cleanup();
        return $result;
    }
    return 0;
}

sub vti_die {
  my (@path,$msg) = @_;
  Vyatta::Config::outputError(@path, $msg);
  exit 1;
}

#
# Check if there are any VTI's defined under 'interface vti'
# but not specified under VPN configuration
# For now just print a warning.
#
sub checkUnrefIntfVti {
    my ($vcIntf, %vtiVpns) = @_;

    my @vtiIntfs = $vcIntf->listNodes("vti");
    foreach my $tunName (@vtiIntfs) {
        if ( ! exists($vtiVpns{ $tunName }) ) {
            print STDOUT "Warning: [interface vti $tunName] defined but not used under VPN configuration\n";
        }
    }

    return;
}
