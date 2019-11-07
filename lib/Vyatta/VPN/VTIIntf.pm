#
# module to find and store exisiting vti tunnels.
#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2017, Brocade Communications Systems, Inc.
# All Rights Reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2012 Vyatta, Inc.
# All Rights Reserved.
#
# Description: Find and store exisiting vti tunnels
#
# **** End License ****
#
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::VTIIntf;

use strict;
use warnings;

use parent qw( Exporter );

our @EXPORT_OK = qw( allocVtiMark deleteVtibyname deleteVtinamepresent
                     discoverVtiIntfs extractRemoteLocal freeVtiMark
                     getVtibyNames getVtiNames isVtimarkpresent
                     isVtinamepresent parseVtiTun );

# Collect set of existing Vti's.
my %existingVtiName = ();
my %existingVtibyName = ();
my %existingVtiMark = ();
my @VtiMarks;
my $vtiMarkBase = 0x90000000;
my $maxMarks = 2048;

sub discoverVtiIntfs {
    my @currentVtis = `/sbin/ip tunnel | grep "^vti"`;

    if ( -f '/opt/vyatta/etc/features/vyatta-security-vpn-ipsec-v1/enable-dataplane-ipsec6' ) {
	my @currentVtis6 = `/sbin/ip -6 tunnel | grep "^vti"`;
	push(@currentVtis, @currentVtis6);
    }

    if (@currentVtis != 0) {
    	my ($remote, $local, $name, $imark, $omark);
    	my $key;
    	foreach my $curVti (@currentVtis) {
    		($remote, $local, $name, $imark, $omark) = parseVtiTun($curVti);
    		$key = "remote $remote local $local";
    		$existingVtiName{$key} = $name;
    		$existingVtiMark{$key} = $omark;
    		$VtiMarks[$omark-$vtiMarkBase] = 1;
            $existingVtibyName{$name} = 1;
    	}
    }
    return;
}

#
# Api takes as input the o/p of 'ip tunnel show' and
#  returns a list with {remote,local,name,mark}
# Example input:
# vti2: ip/ip  remote 12.0.0.2  local 12.0.0.1  ttl inherit  nopmtudisc key 15
#
# or
#
# vti0: ip/ip  remote 10.22.4.5  local 10.22.4.6  ttl inherit  nopmtudisc ikey 0  okey 2415919105
sub parseVtiTun {
	my ($tunop) = @_;
	my ($tunName, $remote, $local, $imark, $omark);
	if ($tunop =~ m/(^vti.*): .*/) {
		$tunName = $1;
	}
	if ($tunop =~ m/remote ([^\s]+)/) {
		$remote = $1;
	}
	if ($tunop =~ m/local ([^\s]+)/) {
		$local = $1;
	}
	if ($tunop =~ m/ikey ([0-9\.]+)/) {
	        $imark = $1;
	} elsif ($tunop =~ m/key ([0-9\.]+)/) {
	        $imark = $1;
	}
	if ($tunop =~ m/okey ([0-9\.]+)/) {
		$omark = $1;
	} elsif  ($tunop =~ m/key ([0-9\.]+)/) {
	        $omark = $1;
	}
	return($remote, $local, $tunName, $imark, $omark);
}

sub extractRemoteLocal {
	my ($key) = @_;
	my ($remote, $local);
	if ($key =~ m/remote ([^\s]+)/) {
		$remote = $1;
	}
	if ($key =~ m/local ([^\s]+)/) {
		$local = $1;
	}
	return($remote, $local);
}

sub isVtinamepresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiName{$key} ) {
		return $existingVtiName{$key};
	}
	return ""; 
}

#
# Pass a referenct to the existing Vti names.
#
sub getVtiNames {
	return (\%existingVtiName);
}

sub deleteVtinamepresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiName{$key} ) {
		delete $existingVtiName{$key};
	}
    return;
}

sub isVtimarkpresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiMark{$key} ) {
		return $existingVtiMark{$key};
	}
	return ""; 
}

sub allocVtiMark {
	for my $cmark (1 .. ($maxMarks-1)) {
		if (! defined($VtiMarks[$cmark])) {
			$VtiMarks[$cmark] = 1;
			return $cmark + $vtiMarkBase ;
		}
	}
	return 0;
}

sub freeVtiMark {
	my ($freeMark) = @_;
	if ($freeMark > 0 && $freeMark < $maxMarks) {
		$VtiMarks[$freeMark] = 0;
	}
	return 0;
}

sub isVtibynamepresent {
    my ($name) = @_;
    if (exists $existingVtibyName{$name} ) {
        return $existingVtibyName{$name};
    }
    return 0;
}

sub deleteVtibyname {
    my ($name) = @_;
    if (exists $existingVtibyName{$name} ) {
        delete $existingVtibyName{$name};
    }
    return;
}

sub getVtibyNames {
    return (\%existingVtibyName);
}

1;
