#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2011-2013 Vyatta, Inc.
# All Rights Reserved.
#
# Description: Script to execute op-mode commands for IPSEC VPN
#
# **** End License ****
#
# Module Vyatta::VPN::OpMode.pm
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::OPMode;

use strict;
use warnings;

use File::Slurp;

use lib "/opt/vyatta/share/perl5";
use Vyatta::VPN::Util qw(conv_id get_daemon_pid ip_cmp);
use Vyatta::VPN::Config qw( get_config_tunnel_desc );
use Vyatta::VPN::Constants qw( DMVPN_CONF IPSEC_CONF );
use Vyatta::Dataplane;

use JSON qw( decode_json);
use IPC::System::Simple qw(capture);

use Carp qw(croak);

# disable warnings on experimental when
no if $] >= 5.018, warnings => "experimental::smartmatch";
use feature qw(switch);

use parent 'Exporter';
our @EXPORT_OK = qw(conv_dh_group conv_enc conv_hash conv_natt conv_id_rev
    conv_bytes conv_ip get_peers_for_cli get_vpnprof_tunnels
    get_conn_for_cli get_connection_status get_peer_ike_status show_ipsec_sa
    add_tunnel_info_description peerSort tunSort
    show_ipsec_sa_detail show_ipsec_sa_peer show_ipsec_sa_peer_detail
    show_ipsec_sa_conn_detail show_ipsec_sa_conn show_ipsec_sa_natt
    show_ipsec_sa_stats show_ipsec_sa_stats_peer show_ipsec_sa_stats_conn
    show_ipsec_status
    show_ike_sa show_ike_status show_ike_sa_status show_ike_sa_peer
    show_ike_sa_natt show_ike_secrets display_ike_sa_brief
    display_ipsec_sa_brief display_ipsec_sa_detail display_ipsec_sa_stats
    show_ipsec_sa_profile show_ipsec_sa_profile_detail
    get_dataplane_ipsec_sad_sas);
our %EXPORT_TAGS = (
    all => [@EXPORT_OK],
    cli => [qw(get_peers_for_cli get_conn_for_cli get_connection_status
        get_peer_ike_status)],
    conv => [qw(conv_dh_group conv_enc conv_hash conv_natt conv_id_rev
        conv_bytes conv_ip )],
    ike => [qw(show_ike_sa show_ike_status show_ike_sa_status
        show_ike_sa_peer show_ike_sa_natt show_ike_secrets)],
    ipsec => [qw(show_ipsec_sa show_ipsec_sa_detail show_ipsec_sa_peer
        show_ipsec_sa_peer_detail show_ipsec_sa_conn_detail
        show_ipsec_sa_conn show_ipsec_sa_natt show_ipsec_sa_stats
        show_ipsec_sa_stats_peer show_ipsec_sa_stats_conn show_ipsec_status
        show_ipsec_sa_profile show_ipsec_sa_profile_detail)],
);

BEGIN {
    use POSIX qw( WIFEXITED );

    my ($sub_gti, $sub_gtip, $sub_gtivpnprof, $sub_gtiprofile);
    require Vyatta::VPN::Charon;
    $sub_gti = \&Vyatta::VPN::Charon::get_tunnel_info;
    $sub_gtip = \&Vyatta::VPN::Charon::get_tunnel_info_peer;
    $sub_gtivpnprof = \&Vyatta::VPN::Charon::get_tunnel_info_vpnprof;
    $sub_gtiprofile = \&Vyatta::VPN::Charon::get_tunnel_info_profile;

    *get_tunnel_info = $sub_gti;
    *get_tunnel_info_peer = $sub_gtip;
    *get_tunnel_info_vpnprof = $sub_gtivpnprof;
    *get_tunnel_info_profile = $sub_gtiprofile;
}

sub conv_dh_group {
    my $dhgrp    = shift;
    my $dh_group = '';
    if ( $dhgrp eq "MODP_768" ) {
        $dh_group = 1;
    }
    elsif ( $dhgrp eq "MODP_1024" ) {
        $dh_group = 2;
    }
    elsif ( $dhgrp eq "MODP_1536" ) {
        $dh_group = 5;
    }
    elsif ( $dhgrp eq "MODP_2048" ) {
        $dh_group = 14;
    }
    elsif ( $dhgrp eq "MODP_3072" ) {
        $dh_group = 15;
    }
    elsif ( $dhgrp eq "MODP_4096" ) {
        $dh_group = 16;
    }
    elsif ( $dhgrp eq "MODP_6144" ) {
        $dh_group = 17;
    }
    elsif ( $dhgrp eq "MODP_8192" ) {
        $dh_group = 18;
    }
    elsif ( $dhgrp eq "ECP_256" ) {
        $dh_group = 19;
    }
    elsif ( $dhgrp eq "ECP_384" ) {
        $dh_group = 20;
    }
    elsif ( $dhgrp eq "<N/A>" ) {
        $dh_group = "n/a";
    }
    else {
        $dh_group = $dhgrp;
    }
    return $dh_group;
}

sub conv_hash {
    my $hash = shift;
    if ($hash =~ /HMAC_(.*)/) {
        $hash = $1;
    } elsif ($hash =~ /AUTH_(.*)/) {
        $hash = $1;
    }
    $hash = lc($hash);

    # legacy hash tokens for show commands as with strongswan 4.x
    #
    # src/libstrongswan/crypto/proposal/proposal_keywords_static.c
    # static const struct proposal_token wordlist[] =
    my %hash_map = (
        "md5_96" => "md5",
        "sha1_96" => "sha1",
        "sha2_256_128" => "sha2_256",
        "sha2_384_192" => "sha2_384",
        "sha2_512_256" => "sha2_512",
        "aes_xcbc_96" => "aesxcbc",
    );

    if (defined($hash_map{$hash})) {
        return $hash_map{$hash};
    }

    return $hash;
}

sub conv_enc {
    my $enc = shift;
    if ( $enc =~ /(.*?)_(.*?)_(.*?)_(.*)/ ) {
        $enc = lc($1) . $4 . lc($2) . $3*8;
    }
    elsif ( $enc =~ /(.*?)_.*?_(.*)/ ) {
        $enc = lc($1) . $2;
        $enc =~ s/^ //g;
    }
    elsif ( $enc =~ /3DES/ ) {
        $enc = "3des";
    }
    return $enc;
}

sub conv_natt {
    my $natt = shift;
    if ( $natt eq 'n/a' || $natt == 0 ) {
        $natt = "no";
    }
    else {
        $natt = "yes";
    }
    return $natt;
}

sub conv_id_rev {
    my (@peers) = @_;

    return unless defined $peers[0];

    @peers = map { /@(.*)/xms ? $1 : $_ } @peers;
    return wantarray ? @peers : $peers[0];
}

sub conv_blocked {
    my ($blocked_state) = @_;

    given ($blocked_state) {
      return 'n/a' when (undef);
      return 'yes' when (1);
      return 'no' when (0);
      default { croak "Unexpected value: $blocked_state" }
    }
}

sub conv_bytes {
    my ($kern_bytes, $dp_bytes) = @_;
    my $bytes = 0;
    if ($kern_bytes ne 'n/a') {
        $bytes += $kern_bytes ;
    }
    if ($dp_bytes) {
        $bytes += $dp_bytes;
    }
    my $suffix = '';
    $bytes =~ s/\s+$//;
    if ( $bytes >= 1073741824 ) {
        $bytes /= 1073741824;
        $suffix = "G";
    }
    elsif ( $bytes >= 1048576 ) {
        $bytes /= 1048576;
        $suffix = "M";
    }
    elsif ( $bytes >= 1024 ) {
        $bytes /= 1024;
        $suffix = "K";
    }
    $bytes = sprintf( "%.1f%s", $bytes, $suffix );
    return $bytes;
}

sub conv_ip {
    my $peerip = shift;
    if (   $peerip =~ /\@.*/
        || $peerip =~ /\%any/ )
    {
        $peerip = "0.0.0.0";
    }
    return $peerip;
}

sub get_vpnprof_tunnels {
    return get_tunnel_info_vpnprof();
}

sub get_all_tunnels {
    return (get_tunnel_info(), get_tunnel_info_vpnprof());
}

sub get_conns {
    my ($file) = @_;
    my $lines = read_file($file, array_ref => 1, err_mode => 'quiet',
                          chomp => 1);
    return unless (defined $lines);

    my %th = ();
    for my $line (@${lines}) {
        next if ( $line =~ /^\#/ );
        if ( $line =~ /peer-(.*?)-tunnel-(.*)/ ) {
            my ( $peer, $tun ) = ( $1, $2 );
            if ( not exists $th{$peer} ) {
                $th{$peer} = {
                    _conns  => [$tun],
                    _peerid => conv_id($peer)
                };
            }
            else {
                push( @{ $th{$peer}->{_conns} }, $tun );
            }
        } elsif ( $line =~ /vpnprof-tunnel-(.*)/ ) {
            my $tun = $1;
            if ( not exists $th{$tun} ) {
                $th{$tun} = {
                    _conns => [$tun],
                    _tunid => $tun
                };
            }
            else {
                push( @{ $th{$tun}->{_conns} }, $tun );
            }
        }
    }
    return %th;
}

sub get_conn_for_cli_vpnprof {
    my $profileid = shift;
    my %th        = get_conns(DMVPN_CONF);
    for my $tun ( keys %th ) {
        for my $conn ( @{ $th{$tun}->{_conns} } ) {
            print $conn, "\n";
        }
    }
    return;
}

sub get_peers_for_cli {
    my %tunnel_hash = get_all_tunnels();
    my @tunnels;
    for my $peer ( keys %tunnel_hash ) {
        push @tunnels, $tunnel_hash{$peer}->{_peerid}
           if defined $tunnel_hash{$peer}->{_peerid};
    }

    for my $tun ( peerSort( @tunnels ) ) {
        print $tun, "\n";
    }

    return;
}

sub get_conn_for_cli {
    my $peerid = shift;
    my %th     = get_conns(IPSEC_CONF);
    for my $peer ( peerSort( keys %th ) ) {
        next if ( not( $th{$peer}->{_peerid} eq $peerid ) );
        for my $conn ( @{ $th{$peer}->{_conns} } ) {
            print $conn, "\n";
        }
    }
    return;
}

sub peerSort {
    my @unsorted = @_;
    return map { $_->[0] }
        sort {
            ip_cmp($a->[1], $b->[1]);
        } map {
            my $tmp = ( split( /-/, $_ ) )[0];
            if ( $tmp =~ /@(.*)/ ) {
                $tmp = $1;
            }
            [ $_, $tmp ]
        } @unsorted;
}

sub tunSort {
    my @unsorted = @_;
    my @sorted = sort { $a->[0] cmp $b->[0]; } @unsorted;
    return @sorted;
}

sub add_tunnel_info_description {
    my ($tunnel_hash_ref) = @_;
    my @peers = map {
        my $a = $tunnel_hash_ref->{$_}->{_peerid}; $a ? $a : ()
    } keys %{$tunnel_hash_ref};

    return unless @peers;

    my %desc = get_config_tunnel_desc(conv_id_rev(@peers));

    for my $tunnel (keys %{ $tunnel_hash_ref }) {
        my $peerid = conv_id_rev($tunnel_hash_ref->{$tunnel}->{'_peerid'});
        if (defined $peerid && exists $desc{$peerid}) {
            $tunnel_hash_ref->{$tunnel}->{'_desc'} = $desc{$peerid};
        }
    }

    return;
}

sub show_ipsec_sa {
    my %tunnel_hash = get_all_tunnels();
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_brief( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_detail {
    my %tunnel_hash = get_all_tunnels();
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_detail( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_peer {
    my $peerid      = shift;
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_brief( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_profile {
    my $profile     = shift;
    my %tunnel_hash = get_tunnel_info_profile($profile);
    display_ipsec_sa_brief( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_profile_detail {
    my $profileid   = shift;
    my %tunnel_hash = get_tunnel_info_profile($profileid);
    display_ipsec_sa_detail( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_stats_peer {
    my $peerid      = shift;
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_stats( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_stats_profile {
    my $profile     = shift;
    my %tunnel_hash = get_tunnel_info_profile($profile);
    display_ipsec_sa_stats( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_stats_conn {
    my ( $peerid, $tun ) = @_;
    my %th = get_tunnel_info_peer($peerid);
    my %tmphash = ();
    for my $peer ( keys %th ) {
        if ( $th{$peer}->{_tunnelnum} eq $tun ) {
            $tmphash{$peer} = \%{ $th{$peer} };
        }
    }
    add_tunnel_info_description( \%tmphash );
    display_ipsec_sa_stats( \%tmphash );
    return;
}

sub show_ipsec_sa_stats_conn_profile {
    ( my $profileid, my $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    my %tmphash = ();
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_stats( \%tmphash );
    return;
}

sub show_ipsec_sa_peer_detail {
    my $peerid      = shift;
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_detail( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_conn_detail {
    my ( $peerid, $tun ) = @_;
    my %th = get_tunnel_info_peer($peerid);
    my %tmphash = ();
    for my $peer ( keys %th ) {
        if ( $th{$peer}->{_tunnelnum} eq $tun ) {
            $tmphash{$peer} = \%{ $th{$peer} };
        }
    }
    add_tunnel_info_description( \%tmphash );
    display_ipsec_sa_detail( \%tmphash );
    return;
}

sub show_ipsec_sa_conn_detail_profile {
    my ( $profileid, $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    my %tmphash = ();
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_detail( \%tmphash );
    return;
}

sub show_ipsec_sa_conn {
    my ( $peerid, $tun ) = @_;
    my %th = get_tunnel_info_peer($peerid);
    my %tmphash = ();
    for my $peer ( keys %th ) {
        if ( $th{$peer}->{_tunnelnum} eq $tun ) {
            $tmphash{$peer} = \%{ $th{$peer} };
        }
    }
    add_tunnel_info_description( \%tmphash );
    display_ipsec_sa_brief( \%tmphash );
    return;
}

sub show_ipsec_sa_conn_vpnprof {
    my ( $profileid, $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    my %tmphash = ();
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_brief( \%tmphash );
    return;
}

sub get_connection_status {
    my ( $peerid, $tun ) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
        if ( $th{$peer}->{_tunnelnum} eq $tun ) {
            return $th{$peer}->{_state};
        }
    }
    return;
}

sub get_peer_ike_status {
    my $peerid = shift;
    my %th     = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
        if ( $th{$peer}->{_ikestate} eq 'up' ) {
            return 'up';
        }
        if ( $th{$peer}->{_ikestate} eq 'init' ) {
            return 'init';
        }
    }
    return 'down';
}

sub show_ipsec_sa_natt {
    my %tunnel_hash = get_all_tunnels();
    my %tmphash     = ();
    for my $peer ( keys %tunnel_hash ) {
        if ( conv_natt($tunnel_hash{$peer}->{_natt}) eq 'yes' ) {
            $tmphash{$peer} = \%{ $tunnel_hash{$peer} };
        }
    }
    display_ipsec_sa_brief( \%tmphash );
    return;
}

sub show_ipsec_status {
    my $process_id = get_daemon_pid();
    my %tunnel_hash = get_all_tunnels();
    my $active_tunnels = 0;
    for my $peer ( keys %tunnel_hash ) {
        if ( defined $tunnel_hash{$peer}->{_state} && $tunnel_hash{$peer}->{_state} eq 'up' ) {
            $active_tunnels++;
        }
    }

    print "IPsec Process Running PID: $process_id\n";
    print "\n$active_tunnels Active IPsec Tunnels\n";
    exit 0;
}

sub show_ike_status {
    my $process_id = get_daemon_pid();

    print <<EOS;
IKE Process Running

PID: $process_id

EOS
    exit 0;
}

sub show_ike_sa {
    my %tunnel_hash = get_all_tunnels();
    add_tunnel_info_description( \%tunnel_hash );
    display_ike_sa_brief( \%tunnel_hash );
    return;
}

sub show_ipsec_sa_stats {
    my %tunnel_hash = get_all_tunnels();
    add_tunnel_info_description( \%tunnel_hash );
    display_ipsec_sa_stats( \%tunnel_hash );
    return;
}

sub show_ike_sa_peer {
    my $peerid      = shift;
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    add_tunnel_info_description( \%tunnel_hash );
    display_ike_sa_brief( \%tunnel_hash );
    return;
}

sub show_ike_sa_natt {
    my %tunnel_hash = get_all_tunnels();
    my %tmphash     = ();
    for my $peer ( keys %tunnel_hash ) {
        if ( conv_natt($tunnel_hash{$peer}->{_natt}) eq 'yes' ) {
            $tmphash{$peer} = \%{ $tunnel_hash{$peer} };
        }
    }
    add_tunnel_info_description( \%tmphash );
    display_ike_sa_brief( \%tmphash );
    return;
}

sub show_ike_secrets {
    print "This command is obsolete\n";
    exit 0;
}

sub display_ipsec_sa_brief {
    my $ref     = shift;
    my %th      = %{$ref};
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        next if $connectid !~ /{\d+}$/xm;
        next unless defined $th{$connectid}->{_state};
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $lip             = conv_ip( $th{$connectid}->{_lip} );
        my $tunnel          = "$peerid-$lip";
        my $peer_configured = conv_id_rev( $th{$connectid}->{_peerid} );
        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _outspi  => $th{$connectid}->{_outspi},
                _lip     => $lip,
                _peerid  => $peer_configured,
                _desc    => $th{$connectid}->{_desc},
                _tunnels => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum},  $th{$connectid}->{_state},
            $th{$connectid}->{_inspi},      $th{$connectid}->{_outspi},
            $th{$connectid}->{_inbytes},    $th{$connectid}->{_outbytes},
            $th{$connectid}->{_encryption}, $th{$connectid}->{_hash},
            $th{$connectid}->{_lifetime},   $th{$connectid}->{_lproto},
            $th{$connectid}->{_atime},     $th{$connectid}->{_dhgrp},
            $th{$connectid}->{_said}
        );
        push( @{ $tunhash{"$tunnel"}->{_tunnels} }, [@tmp] );

    }

    my %sas = get_dataplane_ipsec_sad_sas();

    for my $connid ( peerSort( keys %tunhash ) ) {
        print <<EOH;
Peer ID / IP                            Local ID / IP
------------                            -------------
EOH
        my ( $peerid, $myid ) = $connid =~ /(.*?)-(.*)/;
        printf "%-39s %-39s\n", $peerid, $myid;
        my $desc = $tunhash{$connid}->{_desc};
        print "\n    Description: $desc\n" if ( defined($desc) );
        print <<EOH;

    Tunnel  Id          State  Bytes Out/In   Encrypt       Hash      DH A-Time  L-Time
    ------  ----------  -----  -------------  ------------  --------  -- ------  ------
EOH
        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            my ($tunnum, $state, $inspi, $outspi, $inbytes, $outbytes, $enc,
                $hash,   $life,  $proto, $atime, $dhgrp, $saId
            ) = @{$tunnel};
            my $lip    = $tunhash{$connid}->{_lip};
            my $peerip = conv_ip($peerid);
            my $bytesp = 'n/a';
            $enc  = conv_enc($enc);
            $hash = conv_hash($hash);
            $dhgrp = conv_dh_group($dhgrp);

            $inbytes   = conv_bytes($inbytes, $sas{$inspi}{'bytes'});
            $outbytes  = conv_bytes($outbytes, $sas{$outspi}{'bytes'});
            $bytesp    = "$outbytes/$inbytes";

            my $inblocked  = $sas{$inspi}{'blocked'};
            my $outblocked = $sas{$outspi}{'blocked'};


            if ( $state eq 'up') {
                $inblocked = 0 unless defined($inblocked);
                $outblocked = 0 unless defined($outblocked);

                $state = 'down' if ($outblocked == 1 || $inblocked == 1);
            }


            printf "    %-7s %-11s %-6s %-14s %-13s %-9s %-2s %-7s %-7s\n",
                $tunnum, $saId, $state, $bytesp, $enc, $hash, $dhgrp, $atime, $life;
        }
        print "\n\n";
    }
    return;
}

sub get_dataplane_sad {
    my ( $dpids, $dpsocks ) = Vyatta::Dataplane::setup_fabric_conns();
    my @responses;
    for my $fid ( @{$dpids} ) {
        my $sock = ${$dpsocks}[$fid];
        unless ($sock) {
            warn "Can not connect to dataplane $fid\n";
            next;
        }
        my $response = $sock->execute("ipsec sad");
        next unless defined($response);
        push @responses, $response;
    }
    return '[' . join(',', @responses) . ']';
}

sub get_dataplane_ipsec_sad_sas {
    my %sas;

    my $decoded = decode_json(get_dataplane_sad());

    foreach my $dp_sad ( @{ $decoded } ) {
        foreach my $tunnel( @{ $dp_sad->{'sas'} } ) {
            my $spi = join '', reverse split /(..)/, $tunnel->{'spi'};
            $sas{ $spi } = {};
            $sas{ $spi }{'bytes'} = $tunnel->{'bytes'};
            $sas{ $spi }{'packets'} = $tunnel->{'packets'};
            $sas{ $spi }{'blocked'} = $tunnel->{'blocked'} ? 1 : 0;
        }
    }
    return %sas;
}

sub display_ipsec_sa_detail {
    my $ref     = shift;
    my %th      = %{$ref};
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        next if $connectid !~ /{\d+}$/xm;
        next unless defined $th{$connectid}->{_state};
        my $lip = conv_ip( $th{$connectid}->{_lip} );
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $tunnel = "$peerid-$lip";

        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _peerip     => $th{$connectid}->{_rip},
                _peerid     => $th{$connectid}->{_rid},
                _desc       => $th{$connectid}->{_desc},
                _localip    => $th{$connectid}->{_lip},
                _localid    => $th{$connectid}->{_lid},
                _dhgrp      => $th{$connectid}->{_dhgrp},
                _natt       => $th{$connectid}->{_natt},
                _natsrc     => $th{$connectid}->{_natsrc},
                _natdst     => $th{$connectid}->{_natdst},
                _tunnels    => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum},  $th{$connectid}->{_state},
            $th{$connectid}->{_inspi},      $th{$connectid}->{_outspi},
            $th{$connectid}->{_encryption}, $th{$connectid}->{_hash},
            $th{$connectid}->{_pfsgrp},     $th{$connectid}->{_lsnet},
            $th{$connectid}->{_rsnet},      $th{$connectid}->{_inbytes},
            $th{$connectid}->{_outbytes},   $th{$connectid}->{_lifetime},
            $th{$connectid}->{_atime},     $th{$connectid}->{_lca},
            $th{$connectid}->{_rca},        $th{$connectid}->{_lproto},
            $th{$connectid}->{_rproto},     $th{$connectid}->{_lport},
            $th{$connectid}->{_rport},      $th{$connectid}->{_said}
        );
        push( @{ $tunhash{$tunnel}->{_tunnels} }, [@tmp] );
    }

    my %sas = get_dataplane_ipsec_sad_sas();

    for my $connid ( peerSort( keys %tunhash ) ) {
        my $natt    = conv_natt( $tunhash{$connid}->{_natt} );
        my $peerip  = conv_ip( $tunhash{$connid}->{_peerip} );
        my $localid = $tunhash{$connid}->{_localid};
        if ( $localid =~ /CN=(.*?),/ ) {
            $localid = $1;
        }
        my $peerid = $tunhash{$connid}->{_peerid};
        if ( $peerid =~ /CN=(.*?),/ ) {
            $peerid = $1;
        }
        my $desc = $tunhash{$connid}->{_desc};
        print
            "------------------------------------------------------------------\n";
        print "Peer IP:\t\t$peerip\n";
        print "Peer ID:\t\t$peerid\n";
        print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
        print "Local ID:\t\t$localid\n";
        print "NAT Traversal:\t\t$natt\n";
        print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
        print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
        print "\nDescription:\t\t$desc\n" if ( defined($desc) );
        print "\n";

        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            my ($tunnum,   $state,  $inspi,  $outspi, $enc,
                $hash,     $pfsgrp, $srcnet, $dstnet, $inbytes,
                $outbytes, $life,   $atime, $lca,    $rca,
                $lproto,   $rproto, $lport,  $rport, $saId
            ) = @{$tunnel};
            $enc    = conv_enc($enc);
            $hash   = conv_hash($hash);
            $lport  = 'all' if ( $lport eq '0' );
            $rport  = 'all' if ( $rport eq '0' );
            $pfsgrp = conv_dh_group($pfsgrp);

            $inbytes   = conv_bytes($inbytes, $sas{$inspi}{'bytes'});
            $outbytes  = conv_bytes($outbytes, $sas{$outspi}{'bytes'});

            my $inblocked  = conv_blocked($sas{$inspi}{'blocked'});
            my $outblocked = conv_blocked($sas{$outspi}{'blocked'});

            print "    Tunnel $tunnum:\n";
            print "        State:\t\t\t$state\n";
            print "        Id:\t\t\t$saId\n";
            print "        Inbound SPI:\t\t$inspi\n";
            print "        Outbound SPI:\t\t$outspi\n";
            print "        Encryption:\t\t$enc\n";
            print "        Hash:\t\t\t$hash\n";
            print "        DH Group:\t\t$pfsgrp\n";
            if ( defined $lca ) {
                print "        \n";
                print "        CA:\n";
                foreach my $field ( split( ', ', $lca ) ) {
                    $field =~ s/\"//g;
                    print "            $field\n";
                }
            }

            #print "        Local CA:\t\t$lca\n" if defined($lca);
            #print "        Right CA:\t\t$rca\n" if defined($rca);
            print "        \n";
            print "        Local Net:\t\t$srcnet\n";
            print "        Local Protocol:\t\t$lproto\n";
            print "        Local Port: \t\t$lport\n";
            print "        \n";
            print "        Remote Net:\t\t$dstnet\n";
            print "        Remote Protocol:\t$rproto\n";
            print "        Remote Port: \t\t$rport\n";
            print "        \n";
            print "        Inbound Bytes:\t\t$inbytes\n";
            print "        Outbound Bytes:\t\t$outbytes\n";
            print "        \n";
            print "        Inbound Blocked:\t$inblocked\n";
            print "        Outbound Blocked:\t$outblocked\n";
            print "        \n";
            print "        Active Time (s):\t$atime\n";
            print "        Lifetime (s):\t\t$life\n";
            print "    \n";
        }
        print "\n";
    }
    return;
}

sub display_ipsec_sa_stats {
    my $ref     = shift;
    my %th      = %{$ref};
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;

    my %sas = get_dataplane_ipsec_sad_sas();

    for my $connectid ( keys %th ) {
        next if $connectid !~ /{\d+}$/xm;
        next unless defined $th{$connectid}->{_state};
        my $lip = conv_ip( $th{$connectid}->{_lip} );
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $tunnel = "$peerid-$lip";

        my $inspi = $th{$connectid}->{_inspi};
        my $outspi = $th{$connectid}->{_outspi};

        my $inbytes = $th{$connectid}->{_inbytes};
        my $outbytes = $th{$connectid}->{_outbytes};

        $inbytes   = conv_bytes($inbytes, $sas{$inspi}{'bytes'});
        $outbytes  = conv_bytes($outbytes, $sas{$outspi}{'bytes'});

        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _desc       => $th{$connectid}->{_desc},
                _tunnels    => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum}, $th{$connectid}->{_lsnet},
            $th{$connectid}->{_rsnet},     $inbytes,
            $outbytes,  $th{$connectid}->{_said}
        );
        push( @{ $tunhash{$tunnel}->{_tunnels} }, [@tmp] );
    }
    for my $connid ( peerSort( keys %tunhash ) ) {
        print <<EOH;
Peer ID / IP                            Local ID / IP
------------                            -------------
EOH
        my ( $peerid, $myid ) = $connid =~ /(.*?)-(.*)/;
        printf "%-39s %-39s\n", $peerid, $myid;
        my $desc = $tunhash{$connid}->{_desc};
        print "\n  Description: $desc\n" if ( defined($desc) );
        print <<EOH;

  Tunnel Id         Dir Source Network               Destination Network          Bytes
  ------ ---------- --- --------------               -------------------          -----
EOH
        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            my ( $tunnum, $srcnet, $dstnet, $inbytes, $outbytes, $saId )
                = @{$tunnel};
            printf "  %-6s %-10s %-3s %-28s %-28s %-8s\n",
                $tunnum, $saId, 'in', $dstnet, $srcnet, $inbytes;
            printf "  %-6s %-10s %-3s %-28s %-28s %-8s\n",
                $tunnum, $saId, 'out', $srcnet, $dstnet, $outbytes;
        }
        print "\n\n";
    }
    return;
}

sub display_ike_sa_brief {
    my $ref     = shift;
    my %th      = %{$ref};
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        next if $connectid =~ /{\d+}$/xm;
        my $lip = $th{$connectid}->{_lip};
        $peerid = $th{$connectid}->{_rip};
        my $tunnel = "$peerid-$lip";
        next if ( $th{$connectid}->{_ikestate} eq 'down' );
        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {};
            $tunhash{$tunnel}->{_tunnels} = [];

            $tunhash{$tunnel}->{_desc} = $th{$connectid}->{_desc}
              if defined $th{$connectid}->{_desc};
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum}, $th{$connectid}->{_ikestate},
            $th{$connectid}->{_newestike}, $th{$connectid}->{_ikeencrypt},
            $th{$connectid}->{_ikehash},   $th{$connectid}->{_dhgrp},
            $th{$connectid}->{_ikelife},   $th{$connectid}->{_ikeatime},
            $th{$connectid}->{_ikever}
        );
        push( @{ $tunhash{$tunnel}->{_tunnels} }, [@tmp] );

    }
    for my $connid ( peerSort( keys %tunhash ) ) {
        print <<EOH;
Peer ID / IP                            Local ID / IP
------------                            -------------
EOH
        my ( $peerid, $myid ) = $connid =~ /(.*?)-(.*)/;
        printf "%-39s %-39s\n", $peerid, $myid;
        my $desc = $tunhash{$connid}->{_desc};
        print "\n    Description: $desc\n" if ( defined($desc) );
        print <<EOH;

    State    Encrypt       Hash    D-H Grp  A-Time  L-Time IKEv
    -----  ------------  --------  -------  ------  ------ ----
EOH
        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            my ($tunnum, $state, $isakmpnum, $enc, $hash,
                $dhgrp,  $life,  $ikeatime,    $ikever
            ) = @{$tunnel};
            $enc   = conv_enc($enc);
            $hash  = conv_hash($hash);
            $dhgrp = conv_dh_group($dhgrp);

            printf "    %-6s %-13s %-9s %-8s %-7s %-7s %-2s\n",
                $state, $enc, $hash, $dhgrp, $ikeatime, $life, $ikever;
        }
        print "\n\n";
    }
    return;
}

1;
