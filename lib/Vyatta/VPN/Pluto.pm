#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::Pluto;

use strict;
use warnings;

use parent qw(Exporter);
our @EXPORT_OK = qw(get_tunnel_info get_tunnel_info_peer process_tunnels
                    _make_peer_connection_matcher get_tunnel_info_vpnprof
                    _make_vpnprof_connection_matcher get_tunnel_info_profile);
our %EXPORT_TAGS = (
    ALL => [@EXPORT_OK],
);

use IPC::System::Simple qw(capture);
use Vyatta::VPN::Constants qw(%TUNNEL_DEFAULTS);
use Vyatta::VPN::Util qw(conv_id conv_protocol);
use Vyatta::VPN::Config qw(get_tunnel_id_by_profile
                           get_address_by_tunnel_id);

sub nat_detect {
    my ( $lip, $rip ) = @_;
    my @values;
    if ( $lip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/ ) {
        push( @values, $1, 1, $2 );
    }
    else {
        push( @values, $lip, 0, 'n/a' );
    }
    if ( $rip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/ ) {
        push( @values, $1, $2 );
    }
    else {
        push( @values, $rip, 'n/a' );
    }
    return @values;
}

sub get_tunnel_info {
    my ($matcher) = @_;

    $matcher ||= _make_peer_connection_matcher();

    my $cmd = "ipsec statusall";
    my @ipsecstatus = capture( $cmd );
    chomp( @ipsecstatus );
    return process_tunnels( \@ipsecstatus, $matcher );
}

sub get_tunnel_info_peer {
    my $peer = shift;

    return get_tunnel_info(_make_peer_connection_matcher("\"(peer-$peer-tunnel-.*?)\"") );
}


sub get_tunnel_info_vpnprof {
    return get_tunnel_info(_make_vpnprof_connection_matcher());
}

sub get_tunnel_info_profile {
    my $profile = shift;
    my @tunnels = get_tunnel_id_by_profile($profile);
    my $static_conn_str = 'vpnprof-tunnel-('
                        . join('|', @tunnels)
                        . ').*?';

    my $dyn_conn_str = '(';
    my @addresses;
    for my $tun (@tunnels) {
        push @addresses, get_address_by_tunnel_id($tun);
    }
    $dyn_conn_str .= join('|', @addresses);
    $dyn_conn_str .= ')-to-.*';

    my $search_str = "\"($static_conn_str|$dyn_conn_str)\"";
    return get_tunnel_info(_make_vpnprof_connection_matcher($search_str));
}

sub _make_peer_connection_matcher {
    my ($pattern) = @_;
    $pattern ||= '"(peer-.*?-tunnel-.*?)"';
    my $re = qr/$pattern/;

    return sub {
        my ($line) = @_;

        return if $line !~ $re;

        my $connectid = $1;
        if ( $line =~ /"(peer-.*?-tunnel-.*?)"(\[\d*\])/ ) {
            $connectid .= $2;
        }
        $connectid =~ /peer-(.*?)-tunnel-(.*)/;
        my %init = (
            _peerid => conv_id($1),
            _tunnelnum => $2,
        );
        return ($connectid, \%init);
    };
}

sub _make_vpnprof_connection_matcher {
    my ($pattern) = @_;
    $pattern ||= "\"(vpnprof-tunnel-.*?|.*-to-.*)\"";
    my $re = qr/$pattern/;

    return sub {
        my ($line) = @_;

        return if $line !~ $re;

        my $connectid = $1;
        if ( $line =~ /\"(vpnprof-tunnel-.*?)\"(\[\d*\])/ ) {
            $connectid .= $2;
        }
        my $tunid = "";
        my $peerid = undef;
        if ( ( $connectid =~ /vpnprof-tunnel-(.*)/ ) ) {
            $tunid = $1;
        }
        else {
            # this is for whack connection, we are to find tunid for it.
            $line =~ /\"(.*)-(.*)-to-(.*)\"/;
            $tunid = $1;
            $peerid = $3;
        }
        my %init = (
            _peerid     => $peerid,
            _tunnelnum  => $tunid,
        );
        return ($connectid, \%init);
    };
}

sub process_tunnels {
    my ($ref, $connectid_matcher) = @_;
    my @ipsecstatus = @{$ref};
    my %tunnel_hash = ();
    foreach my $line (@ipsecstatus) {
        if ( my ($connectid, $init_href) = $connectid_matcher->($line) ) {
            if ( not exists $tunnel_hash{$connectid} ) {
                $tunnel_hash{$connectid} = {
                    %TUNNEL_DEFAULTS,
                    %$init_href,
                };
            }
            my $conn = $tunnel_hash{$connectid};
            $line =~ s/---.*\.\.\./.../g
                ;    # remove the next hop router for local-ip 0.0.0.0 case
            if ( $line =~ /IKE proposal: (.*?)\/(.*?)\/(.*)/ ) {
                $conn->{_ikeencrypt} = $1;
                $conn->{_ikehash}    = $2;
                $conn->{_dhgrp}      = $3;
            }

            # both subnets
            elsif ( $line
                =~ /: (.*?)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]===(.*?);/ )
            {
                my ( $lsnet, $lip, $lid, $rip, $rid, $rsnet )
                    = ( $1, $2, $3, $4, $5, $6 );
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_lsnet}  = $lsnet;
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_rsnet}  = $rsnet;
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
            }

            #left subnet
            elsif ( $line =~ /: (.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\];/ ) {
                my ( $lip, $lid, $rip, $rid ) = ( $1, $2, $3, $4 );
                my $lsnet;
                if ( $lip =~ /(.*?)===(.*)/ ) {
                    ( $lsnet, $lip ) = ( $1, $2 );
                }
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
                $conn->{_lsnet}  = $lsnet if ( defined($lsnet) );
            }

            #left subnet with protocols
            elsif ( $line
                =~ /: (.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+);/
                )
            {
                my ($lip, $lid, $lproto, $lport,
                    $rip, $rid, $rproto, $rport
                    )
                    = (
                    $1, $2, conv_protocol($3), $4, $5, $6, conv_protocol($7),
                    $8
                    );
                my $lsnet;
                if ( $lip =~ /(.*?)===(.*)/ ) {
                    ( $lsnet, $lip ) = ( $1, $2 );
                }
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_lsnet}  = $lsnet if ( defined($lsnet) );
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
                $conn->{_lproto} = "$lproto";
                $conn->{_rproto} = "$rproto";
                $conn->{_lport}  = "$lport";
                $conn->{_rport}  = "$rport";
            }

            # both proto/port and subnets
            elsif ( $line
                =~ /: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/
                )
            {
                my ($lsnet, $lip, $lid,    $lproto, $lport,
                    $rip,   $rid, $rproto, $rport,  $rsnet
                    )
                    = (
                    $1, $2, $3, conv_protocol($4),
                    $5, $6, $7, conv_protocol($8),
                    $9, $10
                    );
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_lsnet}  = $lsnet;
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_rsnet}  = $rsnet;
                $conn->{_lproto} = "$lproto";
                $conn->{_rproto} = "$rproto";
                $conn->{_lport}  = "$lport";
                $conn->{_rport}  = "$rport";
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
            }

            # right proto/port only with subnet
            elsif ( $line
                =~ /: (.*)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/
                )
            {
                my ($lsnet, $lip,    $lid,   $rip,
                    $rid,   $rproto, $rport, $rsnet
                ) = ( $1, $2, $3, $4, $5, conv_protocol($6), $7, $8 );
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_lsnet}  = $lsnet;
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_rsnet}  = $rsnet;
                $conn->{_rproto} = "$rproto";
                $conn->{_rport}  = "$rport";
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
            }

            # left proto/port only with subnet
            elsif ( $line
                =~ /: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]===(.*?);/
                )
            {
                my ($lsnet, $lip, $lid, $lproto,
                    $lport, $rip, $rid, $rsnet
                ) = ( $1, $2, $3, conv_protocol($4), $5, $6, $7, $8 );
                ( $lip, my ( $natt, $natsrc ), $rip, my $natdst )
                    = nat_detect( $lip, $rip );
                $conn->{_lid}    = conv_id($lid);
                $conn->{_lip}    = $lip;
                $conn->{_lsnet}  = $lsnet;
                $conn->{_rid}    = conv_id($rid);
                $conn->{_rip}    = $rip;
                $conn->{_rsnet}  = $rsnet;
                $conn->{_lproto} = "$lproto";
                $conn->{_lport}  = "$lport";
                $conn->{_natt}   = $natt;
                $conn->{_natsrc} = $natsrc;
                $conn->{_natdst} = $natdst;
            }
            elsif ( $line =~ /ESP proposal: (.*?)\/(.*?)\/(.*)/ ) {
                $conn->{_encryption} = $1;
                $conn->{_hash}       = $2;
                $conn->{_pfsgrp}     = $3;
            }
            elsif ( $line =~ /STATE_MAIN_I1/ ) {
                $conn->{_ikestate} = "init";
            }
            elsif (
                $line =~ /newest ISAKMP SA: (#\d+); newest IPsec SA: (#\d+);/ )
            {
                if ( $conn->{_newestike} ne 'n/a' ) {
                    if ( $conn->{_newestike} lt $1 ) {
                        $conn->{_newestike} = $1;
                    }
                }
                else {
                    $conn->{_newestike} = $1;
                }
                if ( $conn->{_newestspi} ne 'n/a' ) {
                    if ( $conn->{newestspi} lt $2 ) {
                        $conn->{_newestspi} = $2;
                    }
                }
                else {
                    $conn->{_newestspi} = $2;
                }
            }
            elsif ( $line =~ /ike_life: (\d+)s; ipsec_life: (\d+)s;/ ) {
                $conn->{_ikelife}  = $1;
                $conn->{_lifetime} = $2;
            }
            elsif ( $line =~ /CAs: (.*?)\.\.\.(.*)/ ) {
                $conn->{_lca} = $1;
                $conn->{_rca} = $2;
            }
            my $ike = $conn->{_newestike};
            if ( $ike ne 'n/a' ) {
                if ( $line
                    =~ /$ike: .*ISAKMP SA established.*EVENT_SA_REPLACE in (\d+)s;/
                    )
                {
                    $conn->{_ikeexpire} = $1;
                    my $atime = $conn->{_ikelife} - $conn->{_ikeexpire};
                    if ( $atime >= 0 ) {
                        $conn->{_ikestate} = "up";
                    }
                }
                if ( $line
                    =~ /$ike: .*ISAKMP SA established.*EVENT_SA_EXPIRE in (\d+)s;/
                    )
                {
                    $conn->{_ikeexpire} = $1;
                    my $atime = $conn->{_ikelife} - $conn->{_ikeexpire};
                    if ( $atime >= 0 ) {
                        $conn->{_ikestate} = "up";
                    }
                }
            }
            my $spi = $conn->{_newestspi};
            if ( $spi ne 'n/a' ) {
                if ( $line =~ /$spi: .* esp\.(.*)\@.* \((\d+) bytes.*esp\.(.*)\@.*/ )
                {
                    $conn->{_outspi}   = $1;
                    $conn->{_outbytes} = $2;
                    $conn->{_inspi}    = $3;
                }
                if ( $line =~ /$spi: .* esp\.(.*)\@.* esp\.(.*)\@.* \((\d+) bytes/ ) {
                    $conn->{_outspi}  = $1;
                    $conn->{_inspi}   = $2;
                    $conn->{_inbytes} = $3;
                }
                if ( $line
                    =~ /$spi: .* esp\.(.*)\@.* \((\d+) bytes.* esp\.(.*)\@.* \((\d+) bytes/
                    )
                {
                    $conn->{_outspi}   = $1;
                    $conn->{_outbytes} = $2;
                    $conn->{_inspi}    = $3;
                    $conn->{_inbytes}  = $4;
                }
                if ( $line =~ /$spi: .*EVENT_SA_REPLACE in (\d+)s;/ ) {
                    $conn->{_expire} = $1;
                    my $atime = $conn->{_lifetime} - $conn->{_expire};
                    if ( $atime >= 0 ) {
                        $conn->{_state} = "up";
                    }
                }
                if ( $line =~ /$spi: .*EVENT_SA_EXPIRE in (\d+)s;/ ) {
                    $conn->{_expire} = $1;
                    my $atime = $conn->{_lifetime} - $conn->{_expire};
                    if ( $atime >= 0 ) {
                        $conn->{_state} = "up";
                    }
                }
            }
        }
    }
    return %tunnel_hash;
}

1;
