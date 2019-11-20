#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::Charon;

use strict;
use warnings;

use parent qw(Exporter);
our @EXPORT_OK = qw(charon_ipsec_statusall_parse get_tunnel_info
                    get_tunnel_info_peer _make_peer_connection_matcher
                    _make_vpnprof_connection_matcher
                    get_xfrm_spi_lifetimes get_config_by_conn
                    get_tunnel_info_vpnprof get_tunnel_info_profile);
our %EXPORT_TAGS = ( ALL => [@EXPORT_OK] );

use Carp;
use File::Slurp;
use IPC::System::Simple qw(capture $EXITVAL EXIT_ANY);
use Readonly;
use Time::Local;
use Vyatta::VPN::Constants qw(%TUNNEL_DEFAULTS);
use Vyatta::VPN::Util qw(conv_id conv_proto_port tnormal);
use Vyatta::VPN::Config qw(get_address_by_tunnel_id get_tunnel_id_by_profile);

# disable warnings on experimental when
no if $] >= 5.018, warnings => "experimental::smartmatch";
use feature "switch";

sub get_tunnel_info {
    my ($matcher) = @_;

    $matcher ||= _make_peer_connection_matcher();

    my $cmd = "ipsec statusall";
    my @ipsecstatus = capture(EXIT_ANY, $cmd );
    chomp( @ipsecstatus );

    my %th = charon_ipsec_statusall_parse( \@ipsecstatus, $matcher );

    # get lifetime configuration from 'ip -s xfrm state list spi $spi'
    for my $tunnel (keys %th) {
        my %conn_config = get_config_by_conn($tunnel);
        if (exists $conn_config{'ikelifetime'}) {
            my $ikelife = $conn_config{'ikelifetime'};
            $ikelife =~ s/s$//xms;
            $th{$tunnel}->{'_ikelife'} = $ikelife;
        }

        next if (not $th{$tunnel}->{'_outspi'} or
            $th{$tunnel}->{'_outspi'} eq 'n/a');

        my %spi = get_xfrm_spi_lifetimes($th{$tunnel}->{'_outspi'});
        $th{$tunnel}->{'_lifetime'} = $spi{'_config_expire_add'};
        $th{$tunnel}->{'_atime'} = $spi{'_current_add'};
    }
    return %th;
}

sub get_tunnel_info_peer {
    my $peer = shift;

    my %tunnel_hash = (get_tunnel_info(), get_tunnel_info_vpnprof());
    for my $p ( keys %tunnel_hash ) {
        if (not defined $tunnel_hash{$p}->{_peerid} or
           $tunnel_hash{$p}->{_peerid} !~ /^($peer)[(\[\d*\]|{\d*})]?/xm) {
           delete $tunnel_hash{$p};
        }
    }

    return %tunnel_hash;
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
    $dyn_conn_str .= ')-to-\S*';

    my $search_str = "($static_conn_str|$dyn_conn_str)[:[{^]";
    return get_tunnel_info(_make_vpnprof_connection_matcher($search_str));
}

sub _make_peer_connection_matcher {
    my ($pattern) = @_;
    $pattern ||= '(peer-.*?-tunnel-.*?)[:[{]';
    my $re = qr/^$pattern/m;

    return sub {
        my ($line) = @_;

        return if $line !~ $re;

        my $connectid = $1;

        if ( $line =~ /(peer-.*?-tunnel-.*?|.*-to-.*?)(\[\d*\]|{\d*})/xm ) {
            $connectid .= $2;
        }

        my %init = ();
        if ( $connectid =~ /peer-(.*?)-tunnel-(\d+|vti)[(\[\d*\]|{\d*})]?/xm ) {
            %init = (
                _peerid => conv_id($1),
                _tunnelnum => $2,
            );
        }
        return ($connectid, \%init);
    };
}

sub _make_vpnprof_connection_matcher {
    my ($pattern) = @_;
    $pattern ||= "(vpnprof-tunnel-.*?|.*-to-.*?)[:[{]";
    my $re = qr/$pattern/;

    return sub {
        my ($line) = @_;

        return if $line !~ $re;

        my $connectid = $1;
        if ( $line =~ /(.*-to-.*?)[:[{]/ ) {
            $connectid = $1;
        }
        if ( $line =~ /(vpnprof-tunnel-.*?|.*-to-.*?)(\[\d*\]|{\d*})/ ) {
            $connectid .= $2;
        }

        my $tunid = "";
        my $peerid = undef;
        if ( ( $connectid =~ /vpnprof-tunnel-(tun\d*)/ ) ) {
            $tunid = $1;
        }
        else {
            # this is for whack connection, we are to find tunid for it.
            #
            # peerid is required for the "show ipsec sa profile" and the detailed
            # show command. "Peer ID: ....."
            $line =~ /(.*)-(.*)-to-([^\[:]*)(\[\d+\])?:\ /;
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

sub _charon_ipsec_statusall_parse_connections {
    my ( $connection_matcher, $state_obj, $line ) = @_;

    croak "Wrong number of args" unless (@_ == 3);

    my $tunnel_hash = $state_obj->{'th'};

    my $first_seen = 0;

    # First take care of state transition
    return 'SHUNTED' if $line =~ /^Shunted\ Connections:$/xm;
    return 'ROUTED' if $line =~ /^Routed\ Connections:$/xm;
    return 'SA' if $line =~ /^Security\ Associations\ \(.*\):$/xm;

    my ($connectid, $init_href) = $connection_matcher->($line);

    return if not defined $connectid;

    if ( not exists $tunnel_hash->{$connectid} ) {
        $tunnel_hash->{$connectid} = {
            %TUNNEL_DEFAULTS,
            %{$init_href},
        };
        $first_seen = 1;
    }
    my $conn = $tunnel_hash->{$connectid};

    for ($line) {
        # fprintf("%12s:  %s...%s  %N")
        when (/:\s+(.*?)\.\.\.(.*?)\s+IKEv([^,]*)?/xm) {
            $conn->{_lip} = $1;
            $conn->{_rip} = $2;
            $conn->{_ikever} = ($3 eq '1/2') ? '2+1' : $3;
            $state_obj->{'last_ike_sa'} = $conn;
        }
        # fprintf("%12s:   %s uses ")
        when (/:\s+local:(.*)uses/xm) {
            $state_obj->{'last_ike_sa'} = $conn;
            if (my ($lid) = $1 =~ /\[(.*)\]/xm) {
                $conn->{_lid} = conv_id($lid);
            }
        }
        when (/:\s+remote:(.*)uses/xm) {
            $state_obj->{'last_ike_sa'} = $conn;
            if (my ($rid) = $1 =~ /\[(.*)\]/xm) {
                $conn->{_rid} = conv_id($rid);
            }
        }
        # fprintf("%12s:   child:  %#R=== %#R%N")
        when (/:\s+child:\s+([^\s\[]*)(\[.*\])?\s===\s([^\s\[]*)(\[.*\])?/xm) {

            $conn->{_lsnet} = $1;
            ($conn->{_lproto}, $conn->{_lport}) = conv_proto_port($2) if defined($2);
            $conn->{_rsnet} = $3;
            ($conn->{_rproto}, $conn->{_rport}) = conv_proto_port($4) if defined($4);

            if ($first_seen) {
               my $parent_th = $state_obj->{'last_ike_sa'};
               $state_obj->{'parent_sa_for_child'}->{$connectid} = $parent_th;
               push(@{$state_obj->{'child_sas'}}, $connectid);

               $conn->{_lip} = $parent_th->{_lip};
               $conn->{_rip} = $parent_th->{_rip};
               $conn->{_lid} = $parent_th->{_lid};
               $conn->{_rid} = $parent_th->{_rid};
               $conn->{_ikever} = $parent_th->{_ikever};
            }
        }
#        when (/${re_peer}/) {
#            croak "Unexpected data: $line"
#            if not exists $tunnel_hash->{$1};
#        }
        default { return }
    }

    return;
}

sub _charon_ipsec_statusall_parse_routed_connections {
    my ( $connection_matcher, $state_obj, $line ) = @_;

    croak "Wrong number of args" unless (@_ == 3);

    # First take care of state transition
    return 'SA' if $line =~ /^Security\ Associations\ \(.*\):$/xm;

    return;
}

sub _charon_ipsec_statusall_parse_shunted_connections {
    my ( $connection_matcher, $state_obj, $line ) = @_;

    croak "Wrong number of args" unless (@_ == 3);

    # First take care of state transition
    return 'ROUTED' if $line =~ /^Routed\ Connections:$/xm;
    return 'SA' if $line =~ /^Security\ Associations\ \(.*\):$/xm;

    return;
}

sub _charon_ipsec_statusall_parse_security_associations {
    my ( $connection_matcher, $state_obj, $line ) = @_;

    # First take care of state transition
    # NOTE: no state transisitions from this state

    my $tunnel_hash = $state_obj->{'th'};

    my $first_seen = 0;

    my ($connectid, $init_href) = $connection_matcher->($line);
    return if not $connectid;

    if ( not exists $tunnel_hash->{$connectid} ) {
        $tunnel_hash->{$connectid} = {
            %TUNNEL_DEFAULTS,
            %{$init_href},
        };
        $first_seen = 1;
    }

    my $conn = $tunnel_hash->{$connectid};

    # fprintf("%12s[%d]: %N")
    return if $line !~ /^\S+([{[]\d+[]}]):/xm;
    my $sa_id  = $1;

    # IKE SA
    if ($sa_id =~ /\[\d+\]/xm) {
        $state_obj->{'last_ike_sa'} = $conn;
        for ($line) {
            when (/:\sCONNECTING/xm) {
                $conn->{_ikestate} = 'init';
                continue;
            }
            when (/:\sESTABLISHED\ (\d+)\ (.*?)\ ago/xm) {
                $conn->{_ikestate} = 'up';
                ( $conn->{_ikeatime} ) = tnormal($1, $2);
                ( $conn->{_newestike} ) = $sa_id =~ /(\d+)/xm;
                continue;
            }
            # fprintf(", %#H[%Y]...%#H[%Y]\n")
            # NOTE: Vyatta specific strongswan patch prints additional [$port] brackets.
            when (/,\s(.*?)\[(.*?)\]\[(.*?)\]\.\.\.(.*?)\[(.*?)\]\[(.*?)\]$/xm) {
                $conn->{_lip}    = $1;
                $conn->{_natsrc} = $2;
                $conn->{_lid}    = conv_id($3);
                $conn->{_rip}    = $4;
                $conn->{_natdst} = $5;
                $conn->{_rid}    = conv_id($6);

                $conn->{_peerid} = $conn->{_rip} unless defined $conn->{_peerid};
            }
            # NOTE: Vanilla strongswan - WITHTOUT patch which prints additional [$port] brackets.
            when (/,\s(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]$/xm) {
                $conn->{_lip}    = $1;
                $conn->{_lid}    = conv_id($2);
                $conn->{_rip}    = $3;
                $conn->{_rid}    = conv_id($4);

                $conn->{_peerid} = $conn->{_rip} unless defined $conn->{_peerid};
            }
            # fprintf("%12s[%d]: %N SPIs: %.16"PRIx64"_i%s %.16"PRIx64"_r%s")
            when (/:\sIKEv(\d)\sSPIs:\s.*?_i\*?\s.*?_r\*?/xm) {
                # otherwise not interested in IKE SPI
                $conn->{_ikever} = $1;
            }
            # fprintf("%12s[%d]: IKE proposal: %s\n")
            when (/:\sIKE\sproposal:\s(.*?)\/(.*?)\/(.*?)\/(.*?)$/xm) {
                $conn->{_ikeencrypt} = $1;
                $conn->{_ikehash}    = $2;
                $conn->{_ikeprf}     = $3;
                $conn->{_dhgrp}      = $4;
            }
            default { return }
        }
    }
    # CHILD SA
    elsif ($sa_id =~ /{\d+}/xm) {
        for ($line) {
            $conn->{_said} = $sa_id =~ tr/{}//dr;
            when (/:\s+(INSTALLED|CREATED|ROUTED|UPDATING|REKEYING|DELETING|DESTROYING),/xm) {
                $conn->{_state} = 'up';
                continue;
            }
            when (/:\s+INSTALLING,/xm) {
                $conn->{_state} = 'down';
                continue;
            }
            # rekeyed CHILD_SA are stale until they expire. Ignore them.
            when (/:\s+REKEYED,/xm) {
                $conn->{_state} = undef;
                continue;
            }
            # with 5.3.0 reqid got added in stroke_list.c
            # no longer unique per CHILD_SA
            when (/,\ reqid\ (\d+),/xm) {
                $conn->{_reqid} = $1;
                continue;
            }
            # fprintf(", %N%s SPIs: %.8x_i %.8x_o")
            when (/,\sESP\s([\s\w]+[^\s])?\s?SPIs:\s(.*?)_i\s(.*?)_o/xm) {
                $conn->{_natt} = (defined($1) and $1 eq "in UDP") ? 1 : 0;
                $conn->{_inspi} = $2;
                $conn->{_outspi} = $3;
                ( $conn->{_newestspi} ) = $sa_id =~ /(\d+)/xm;
            }
            # parse proposal and inbytes in one go
            # fprintf(", %" PRIu64 " bytes_i")
            when (/:\s+(.*?),\s(\d+)\sbytes_i/xm) {
                my ($proposal, $inbytes) = ($1, $2);
                # strip extended sequence numbers
                $proposal =~ s/\/ESN$//xm;
                my ($enc, $mac, $dh) = split('/', $proposal);
                $conn->{_encryption} = $enc;
                if ($mac) {
					if ($mac =~ /MODP_(.*)|ECP_(.*)/) {
                    	$conn->{_pfsgrp} = $mac;
                        $conn->{_hash} = 'null';
					}
					else {
                    	$conn->{_hash} = $mac;
					}
                } else {
                        $conn->{_hash} = 'null';
                }
                if ($dh) {
                    $conn->{_pfsgrp} = $dh;
                }
                $conn->{_inbytes} = $inbytes;
                continue;
            }
            # fprintf(", %" PRIu64 " bytes_o")
            when (/,\s(\d+)\sbytes_o/xm) {
                $conn->{_outbytes} = $1;
            }
            when (/:\s+([^\s\[]*)(\[.*\])?\s===\s([^\s\[]*)(\[.*\])?/xm) {
                $conn->{_lsnet} = $1;
                ($conn->{_lproto}, $conn->{_lport}) = conv_proto_port($2) if defined($2);
                $conn->{_rsnet} = $3;
                ($conn->{_rproto}, $conn->{_rport}) = conv_proto_port($4) if defined($4);
            }
        }

        if ($first_seen) {
           my $parent_th = $state_obj->{'last_ike_sa'};
           $state_obj->{'parent_sa_for_child'}->{$connectid} = $parent_th;
           push(@{$state_obj->{'child_sas'}}, $connectid);

           $conn->{_lip} = $parent_th->{_lip};
           $conn->{_rip} = $parent_th->{_rip};
           $conn->{_lid} = $parent_th->{_lid};
           $conn->{_rid} = $parent_th->{_rid};
           $conn->{_peerid} = $parent_th->{_peerid};
        }
    }
    else {
        croak "Unexpected data: $line";
    }

    return;
}

Readonly::Hash my %charon_ipsec_statusall_parser => (
    INIT => sub {
        my ( $connection_matcher, $state_obj, $line ) = @_;
        return 'CONN' if $line =~ /^Connections:$/xm;
        return;
    },
    CONN => \&_charon_ipsec_statusall_parse_connections,
    SHUNTED => \&_charon_ipsec_statusall_parse_shunted_connections,
    ROUTED => \&_charon_ipsec_statusall_parse_routed_connections,
    SA   => \&_charon_ipsec_statusall_parse_security_associations,
);

#
# Parse the output of charons 'ipsec statusall'
#
# Comments of the format 'fprint(fmt)' refer to the strongswan source file
# strongswan/src/libcharon/plugins/stroke/stroke_list.c
#
sub charon_ipsec_statusall_parse {
    my ($ipsecstatus, $connection_matcher) = @_;
    my %tunnel_hash = ();
    my $dispatch = \%charon_ipsec_statusall_parser;
    my $state = 'INIT';
    my %state_obj = ();

    $state_obj{'th'} = \%tunnel_hash;
    $state_obj{'last_ike_sa'} = undef;
    $state_obj{'child_sas'} = ();
    $state_obj{'parent_sa_for_child'} = ();

    foreach my $line (@{$ipsecstatus}) {
        croak "Undefined state" if ! defined($dispatch->{$state});
        if ( my $next_state = $dispatch->{$state}->($connection_matcher,
                                                    \%state_obj, $line) ) {
            #print "Transition: $state -> $next_state\n";
            $state = $next_state;
        }
    }

    foreach my $child_sa (@{$state_obj{'child_sas'}}) {
        my $parent_th = $state_obj{'parent_sa_for_child'}->{$child_sa};

        $tunnel_hash{$child_sa}->{_ikever} = $parent_th->{_ikever};
        $tunnel_hash{$child_sa}->{_ikestate} = $parent_th->{_ikestate};
        $tunnel_hash{$child_sa}->{_newestike} = $parent_th->{_newestike} if defined $parent_th->{_newestike};
        $tunnel_hash{$child_sa}->{_lip} = $parent_th->{_lip};
        $tunnel_hash{$child_sa}->{_lid} = $parent_th->{_lid};
        $tunnel_hash{$child_sa}->{_rip} = $parent_th->{_rip};
        $tunnel_hash{$child_sa}->{_rid} = $parent_th->{_rid};
        $tunnel_hash{$child_sa}->{_ikeencrypt} = $parent_th->{_ikeencrypt} if defined $parent_th->{_ikeencrypt};
        $tunnel_hash{$child_sa}->{_ikehash} = $parent_th->{_ikehash} if defined $parent_th->{_ikehash};
        $tunnel_hash{$child_sa}->{_ikeprf} = $parent_th->{_ikeprf} if defined $parent_th->{_ikeprf};
        $tunnel_hash{$child_sa}->{_dhgrp} = $parent_th->{_dhgrp} if defined $parent_th->{_dhgrp};
    }


    # If there is an active IKE_SA in the tunnel_hash:
    #  vpnprof-tunnel-tun0[X]
    # ... delete the stale IKE_SA counter part:
    # vpnprof-tunnel-tun0
    #
    foreach my $tunnel (keys %tunnel_hash) {

        next if $tunnel =~ /(\[\d+\]|{\d+})/xm;
        foreach my $active_sa (keys %tunnel_hash) {
            if ($active_sa =~ /^$tunnel(\[\d+\]|{\d+})/xm) {
                delete $tunnel_hash{$tunnel};
                last;
            }
        }



    }

    return %tunnel_hash;
}

sub get_xfrm_spi_lifetimes {
    my ($spi) = @_;

    if ($spi !~ /^0x/xms) {
        $spi = "0x$spi";
    }

    my $cmd = "ip -s xfrm state list spi $spi";
    my @text = capture( $cmd );
    chomp( @text );

    my %lifetimes;

    for my $line (@text) {
        if ($line =~ /expire\sadd:.*,\shard\s(\d+)\(sec\)$/xm) {
            $lifetimes{'_config_expire_add'} = $1;
        }
        if ($line =~ /add\s(.*)\suse\s.*$/xm) {
            my ($year,$mon,$mday,$hour,$min,$sec) = split(/[\s:-]+/xm, $1);
            $mon -= 1;
            $year -= 1900;

            my $now = time;
            my $dp_time = timegm($sec,$min,$hour,$mday,$mon,$year);
            my $delta = $now - $dp_time;
            $lifetimes{'_current_add'} = $delta;
        }
    }

    return %lifetimes;
}

sub  trim {
    my $s = shift;
    $s =~ s/^\s+|\s+$//xmsg;
    return $s
};

sub get_config_by_conn {
    my ($conn) = @_;
    $conn =~ s/(\{\d+}|\[\d+\])//xms;
    my $conn_re = qr/conn\s+$conn/xms;

    my $file = '/etc/ipsec.conf';
    my $text = read_file( $file, err_mode => 'carp' );

    # the ipsec.conf files we parse is generated by us so there is no need to
    # strip trailing comments
    my %config;
    if ($text =~ /^$conn_re$
                  (.*)
                  ^\#$conn_re$/xms) {
        my @lines = grep {!/^\#/} split /\n/, trim($1);
        %config = map { split /=/, $_, 2 } @lines;
    }

    return %config;
};

1;
