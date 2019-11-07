#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2015-2017, Brocade Communications Systems, Inc.
# All Rights Reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2005-2013 Vyatta, Inc.
# All Rights Reserved.
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::Config;

use strict;
use warnings;
use Readonly;
use Carp;
use File::Slurp qw( write_file );

use parent qw(Exporter);

our @EXPORT_OK = qw($LOCAL_KEY_FILE_DEFAULT rsa_get_local_key_file
    validate_local_key_file get_ike_modp_default conv_pfs_to_dh_group
    generate_conn_ike_proposal generate_conn_esp
    write_charon_logging_conf generate_charon_logging
    conv_protocol_all
    get_config_tunnel_desc get_tunnel_id_by_profile
    get_address_by_tunnel_id
    get_profiles_for_cli);
our %EXPORT_TAGS = ( ALL => [@EXPORT_OK] );

use Vyatta::Config;
use Vyatta::Configd;
use NetAddr::IP;

Readonly our $LOCAL_KEY_FILE_DEFAULT =>
    '/opt/vyatta/etc/config/ipsec.d/rsa-keys/localhost.key';

Readonly our $CONFIG_KEYFILE_PATH =>
    'rsa-keys local-key file';

sub rsa_get_local_key_file {
    my $file = $LOCAL_KEY_FILE_DEFAULT;

    #
    # Read configuration tree
    #
    my $vc = Vyatta::Config->new('security vpn');
    # Use appropriate function for being (or not) in config session
    my $returnValue = $vc->inSession() ?
        \&Vyatta::Config::returnValue : \&Vyatta::Config::returnOrigValue;
    my $key_file_override = $returnValue->($vc, $CONFIG_KEYFILE_PATH);

    #
    # We'll assume validation for valid path/file was handled in the
    # commit.
    #
    $file = $key_file_override if defined($key_file_override);

    return $file;
}

# Sanity check the usr specified local_key_file
#
# 1). Must start with "/"
# 2). Only allow alpha-numeric, ".", "-", "_", or "/".
# 3). Don't allow "//"
# 4). Verify that it's not a directory
#
sub validate_local_key_file {
    my ($local_key_file) = @_;

    if ( $local_key_file ne $LOCAL_KEY_FILE_DEFAULT ) {
        if ( $local_key_file !~ /^\// ) {
            croak "Invalid local RSA key file path \"$local_key_file\"."
                . "  Does not start with a '/'.\n";
        }
        if ( $local_key_file =~ /[^a-zA-Z0-9\.\-\_\/]/g ) {
            croak "Invalid local RSA key file path \"$local_key_file\"."
                . " Contains a character that is not alpha-numeric and not '.', '-', '_', '/'.\n";
        }
        if ( $local_key_file =~ /\/\//g ) {
            croak "Invalid local RSA key file path \"$local_key_file\"."
                . " Contains string \"//\".\n";
        }
        if ( -d $local_key_file ) {
            croak "Invalid local RSA key file path \"$local_key_file\"."
                . " Path is a directory rather than a file.\n";
        }
    }

    return 1;
}

=item get_config_tunnel_desc()

Returns a %tunnel_info with the description for each peer. The description is
taken from the Vyatta configuration.

=cut

sub get_config_tunnel_desc {
    my @peers = @_;
    my %tunnel_info;

    my $vc = Vyatta::Config->new();
    $vc->setLevel('security vpn ipsec site-to-site');

    for my $peer (@peers) {
        my $desc = $vc->returnEffectiveValue("peer $peer description");
        if ($desc) {
            $tunnel_info{$peer} = $desc;
        }
    }

    return %tunnel_info;
}

my %dh_group_to_modp = (
    'dh-group2'  => 'modp1024',
    'dh-group5'  => 'modp1536',
    'dh-group14' => 'modp2048',
    'dh-group15' => 'modp3072',
    'dh-group16' => 'modp4096',
    'dh-group17' => 'modp6144',
    'dh-group18' => 'modp8192',
    'dh-group19' => 'ecp256',
    'dh-group20' => 'ecp384'
);

#
# Returns the modp representation for the dh-group or the default groups
#
#
sub get_ike_modp_default {
    my ($dh_group) = @_;

    croak "This only makes sense in a list context!" if not wantarray;
    croak if $dh_group && $dh_group !~ /^(dh-group)?\d+$/;

    # These defaults are from default_ike_groups[] in src/pluto/alg_info.c
    my @default_ike_groups = ( 'modp1536', 'modp1024' );
    return @default_ike_groups if not $dh_group;
    return ( $dh_group_to_modp{$dh_group} )
        if $dh_group =~ /^dh-group/;
    return ( $dh_group_to_modp{'dh-group' . $dh_group} )
        if $dh_group;

    croak "Could not produce an IKE MODP representation.";
}

sub conv_protocol_all {
    my ($proto) = @_;

    if ($proto eq 'all') {
        return "%any";
    }

    if ($proto eq 'ipip') {
        return "ipencap";
    }

    return $proto;
}

sub conv_pfs_to_dh_group {
    my ($pfs) = @_;

    # enable means use same DH group as our IKE group
    croak "Unable to handle this here" if $pfs eq 'enable';
    return '' if $pfs eq 'disable';

    return $dh_group_to_modp{$pfs};
}

sub generate_conn_ike_proposal {
    my ( $encryption, $hash, $dh_group ) = @_;

    return if !$encryption || !$hash;

    my $enc_hash = $encryption;
    $enc_hash .= "-$hash" if $hash ne 'null';

    my $genout = $enc_hash;
    if ( $dh_group ) {
        my $modp = $dh_group_to_modp{'dh-group' . $dh_group};
        croak "Invalid diffie-hellman group: $dh_group" if not $modp;
        $genout .= "-$modp";
    } else {
        # defaults from default_ike_groups[] in src/pluto/alg_info.c
        $genout .= "-modp1536,$enc_hash-modp1024";
    }

    return $genout;
}

sub generate_conn_esp {
    my ( $enc, $mac, $dh ) = @_;
    my $retval = "$enc";

    $retval .= "-$mac" if defined $mac && $mac ne 'null';

    $retval .= "-$dh" if defined $dh && $dh ne '';

    return $retval;
}

# only translate the plutodebug subset that the Vyatta Yang model supports
Readonly my %plutodebug_to_charon => (
    control  => 'cfg 3, knl 3, lib 3',
    crypt    => 'asn 3, enc 3, ike 3',
    emitting => 'net 2, enc 2',
    parsing  => 'net 2, enc 2',
    private  => 'chd 3, ike 4, mgr 2',
    raw      => 'net 3'
);

sub generate_charon_logging {
    my @logmodes = @_;
    my %charon_subsystems;

    my $output_default = '1';

    # special handling for "all", "minimal" and "none"
    if (grep {/^all$/} @logmodes) {
        $output_default = '2'  ;

        # silence noise
        $charon_subsystems{'enc'} = '1';
        $charon_subsystems{'job'} = '1';
        $charon_subsystems{'mgr'} = '1';
        $charon_subsystems{'net'} = '1';
    } elsif (grep {/^minimal$/} @logmodes) {
        $output_default = '-1';

        $charon_subsystems{'app'} = '1';
        $charon_subsystems{'cfg'} = '1';
        $charon_subsystems{'dmn'} = '1';
        $charon_subsystems{'ike'} = '1';
        $charon_subsystems{'mgr'} = '1';
    }

    $output_default = '-1' if grep {/^none$/} @logmodes;

    # generate subsystem entries
    foreach my $mode (@logmodes) {
        next if !defined $plutodebug_to_charon{$mode};

        %charon_subsystems = (
            %charon_subsystems,
            map {split} split /,/,
            $plutodebug_to_charon{$mode}
        );
    }

    my @charon_subsystems
        = map { "$_ = $charon_subsystems{$_}" } keys %charon_subsystems;

    my $output_subsystems
        = @charon_subsystems
        ? join( "\n            ", @charon_subsystems )
        : '# <subsystem> = <default>';

    my $output = << "END";
charon {
    syslog {
         daemon {
            # Default loglevel.
            default = $output_default

            # Loglevel for a specific subsystem.
            $output_subsystems

            # prepend connection name, simplifies grepping
            ike_name = yes
         }
    }
}
END

    return $output;
}

sub write_charon_logging_conf {
    my ( $vc, $filename ) = @_;

    $filename = '/etc/strongswan.d/charon-logging.conf'
        if !defined $filename;

    my $charon_logging = << "END";
# generated by vpn-config.pl
END
    $charon_logging .= generate_charon_logging(
        $vc->returnValues('ipsec logging log-modes') );
    write_file( $filename, $charon_logging );
    return;
}

sub get_tunnel_id_by_profile {
    my ($profile) = @_;

    my $vc = Vyatta::Config->new('security vpn ipsec');
    my @tunnels = $vc->listOrigNodes("profile $profile bind tunnel");

    return @tunnels;
}

sub get_address_by_tunnel_id {
    my ($tun) = @_;

    my $vc = Vyatta::Config->new();
    my @addresses = $vc->returnOrigValues("interfaces tunnel $tun address");

    # drop mask length
    my @result = map { (my $addr = $_) =~ s/\/.*//; $addr } @addresses;

    return @result;
}

sub get_profiles_for_cli {
    my $vc = Vyatta::Config->new('security vpn ipsec');
    my @profiles = $vc->listOrigNodes('profile');

    for my $prof (@profiles) {
        print $prof, "\n";
    }
    return;
}

1;
