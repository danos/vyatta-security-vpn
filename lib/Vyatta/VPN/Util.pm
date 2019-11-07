#
# Module: Vyatta::VPN::Util.pm
#
# **** License ****
# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2014-2016, Brocade Communications Systems, Inc.
# All Rights Reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2005-2013 Vyatta, Inc.
# All Rights Reserved.
#
# **** End License ****
#

# SPDX-License-Identifier: GPL-2.0-only

package Vyatta::VPN::Util;

use strict;
use warnings;

# disable warnings on experimental when
no if $] >= 5.018, warnings => "experimental::smartmatch";
use feature qw(switch);

use parent qw(Exporter);
our @EXPORT_OK = qw(as_raw_key conv_id conv_protocol enableICMP get_daemon_pid
                    is_tcp_udp is_vpn_running rfc2537_to_rsa_pubkey
                    rsa_pubkey_to_rfc2537 conv_proto_port
                    rsa_get_local_pubkey rsa_public_digest vpn_debug uniq
                    ip_cmp get_pki_key_type rsa_key_from_raw_key vpn_die
                    vpn_exec vpn_log tnormal get_intf conv_intf);
our %EXPORT_TAGS = ( ALL => [@EXPORT_OK] );

use POSIX qw(strftime);
use Carp qw(croak carp);
use Convert::ASN1;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use Digest::MD5 qw(md5);
use MIME::Base64;
use File::Slurp;
use Socket qw(AF_INET AF_INET6 inet_pton);
use IPC::Open2;

my $LOGFILE = '/var/log/vyatta/ipsec.log';

sub get_daemon_pid {
    # NOTE: This doesn't use File::Slurp on purpose because:
    #  1. this simplifies the error case handling (empty string)
    #  2. it simplifies the unittest as well (one readpipe mocking only)
    my $process_id = qx(cat /var/run/charon.pid 2>/dev/null);
    chomp $process_id;

    # return undef if pid file is empty or missing
    return if $process_id eq '';

    # check pid against running processes
    #
    # NOTE: we don't use kill(0, $pid) on purpose because that fails if we
    #       are not allowed to send signals to the process.
    my @pids = qx(pgrep charon 2>/dev/null);
    chomp @pids;

    return $process_id if ( grep { /^$process_id$/ } @pids );

    # return undef is daemon is not running
    return;
}

sub is_vpn_running {
    my $result = qx(systemctl is-active strongswan);
    chomp $result;
    return ($result eq 'active');
}

sub get_protocols {
  my @protocols = read_file( '/etc/protocols' );

  my %protohash = ();
  foreach my $line (@protocols) {
    next if ($line =~ /^\#/);
    if ($line =~ /(\S+)\s+(\d+)\s+(\S+)\s+\#(.*)/){
      my ($name, $number, $desc) = ($1,$2,$4);
      if (not exists $protohash{$number}){
        $protohash{$number} = {
          _name => $name,
          _number => $number,
          _desc => $desc
        };
      }
    }
  }
  return %protohash;
}
 
sub conv_protocol {
  my ($proto) = @_;
  my %protohash = get_protocols();
  foreach my $key (keys %protohash){
    if ("$key" == "$proto") {
      return $protohash{$key}->{_name};
    }
  }
  return $proto;
}


sub is_tcp_udp {
  my ($protocol) = @_;
  return 1 if (($protocol eq '6')  || ($protocol eq 'tcp') ||
               ($protocol eq '17') || ($protocol eq 'udp'));
  return 0;
}

###############################################################################

=item rsa_get_local_pubkey

This function returns the RSA public key part for the @file given. The
input file format could be RAW or PEM.

=cut

###############################################################################

sub rsa_get_local_pubkey {
    my ($file) = @_;

    my @lines = read_file($file, err_mode => 'quiet', chomp => 1);
    return unless @lines;

    # extract RFC 2537 formated pubkey
    foreach my $line (@lines) {
        my $pubkey;
        if (($pubkey) = ($line =~ m/\s+\#pubkey=(\S+)/)) {
            return rfc2537_to_rsa_pubkey($pubkey);
        }
    }

    # only get here if didn't find a RAW format key
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key(join("\n", @lines));
    my ($n, $e, $d, $p, $q) = $rsa_priv->get_key_parameters();

    return Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);
}

sub rfc2537_to_rsa_pubkey {
    my ($str) = @_;

    # drop RFC-2537 adornment
    $str =~ s/^0s//;

    my $raw = decode_base64($str);

    # decompose string into component fields
    my ($len, $len2) = unpack('Cn', $raw);

    my $offset = ($len > 0) ? 1 : 3;
    $len ||= $len2;

    my $e = Crypt::OpenSSL::Bignum->new_from_bin(substr($raw, $offset, $len));
    my $n = Crypt::OpenSSL::Bignum->new_from_bin(substr($raw, $offset + $len));

    # and construct public key from public exponent and modulus (e, n)
    my $rsa = Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);

    return $rsa;
}

sub rsa_pubkey_to_rfc2537 {
    my ($rsa) = @_;

    my ($n, $e) = $rsa->get_key_parameters();
    return format_en($e->to_bin(), $n->to_bin());
}

sub rsa_public_digest {
    my ($rsa, $func) = @_;

    # default to MD5 if no digest function given
    $func = \&Digest::MD5::md5 if (@_ < 2);

    my $der = $rsa->get_public_key_x509_string();

    # remove the delimiter strings
    my $base64 = join('', grep { !/^-----(BEGIN|END) PUBLIC KEY-----$/m } split("\n", $der));

    # extract the base64 (PEM) encoded ASN1 object and return its hash
    my $raw = decode_base64($base64);

    return &{$func}($raw);
}

sub vpn_debug {
    my @args = @_;
    my $timestamp = strftime("%Y%m%d-%H:%M.%S", localtime);

    open my $log, '>>', "/var/log/vpn-debug.log"
	or return;
    print {$log} "$timestamp: ", @args , "\n";
    close $log;
    return;
}

sub vpn_system {
    my ($cmdline) = @_;
    vpn_debug("START      $cmdline");
    my $ret = system($cmdline);
    if ($ret) {
	vpn_debug("END ERROR  $cmdline");
    } else {
	vpn_debug("END OK     $cmdline");
    }
    return;
}

sub enableICMP {
    my ($enable) = @_;
    
    opendir my $dir, '/proc/sys/net/ipv4/conf/' 
	or return;
    my @nodes = grep { !/^\./ } readdir $dir;
    closedir $dir;
    
    foreach my $node (@nodes) {
        write_file("/proc/sys/net/ipv4/conf/$node/accept_redirects", $enable);
        write_file("/proc/sys/net/ipv4/conf/$node/send_redirects", $enable);
    }
    return 1;
}

# per RFC-2537, section 2 "RSA Public KEY Resource Records"
sub format_rfc2537
{
    my ($e, $n) = @_;

    return pack('ca*a*', length($e), $e, $n);
}

# per datatot.c in openswan
sub format_en
{
    my ($e, $n) = @_;

    my $result = '0s' . encode_base64(format_rfc2537($e, $n), '');

    return $result;
}

sub as_raw_key {
    my ($rsa, $name, $timestamp) = @_;

    my $bits = $rsa->size() * 8;

    my ($n, $e, $d, $p, $q, $e1, $e2, $c) = $rsa->get_key_parameters();

    my $result = '';

    $result .= sprintf ": RSA\t{\n\t# RSA %d bits   %s   %s\n\t# for signatures only, UNSAFE FOR ENCRYPTION\n", $bits, $name, scalar localtime($timestamp);
    $result .= sprintf "\t#pubkey=%s\n", format_en($e->to_bin(), $n->to_bin());
    $result .= sprintf "\tModulus: 0x%s\n", lc($n->to_hex());
    $result .= sprintf "\tPublicExponent: 0x%s\n", lc($e->to_hex());
    $result .= "\t# everything after this point is secret\n";
    $result .= sprintf "\tPrivateExponent: 0x%s\n", lc($d->to_hex());
    $result .= sprintf "\tPrime1: 0x%s\n", lc($p->to_hex());
    $result .= sprintf "\tPrime2: 0x%s\n", lc($q->to_hex());
    $result .= sprintf "\tExponent1: 0x%s\n", lc($e1->to_hex());
    $result .= sprintf "\tExponent2: 0x%s\n", lc($e2->to_hex());
    $result .= sprintf "\tCoefficient: 0x%s\n", lc($c->to_hex());
    $result .= "\t}\n# do not change the indenting of that \"}\"\n";

    return $result;
}

sub is_ipv4 {
    my $addr = shift;
    return (defined inet_pton(AF_INET, $addr)) ? 1 : 0;
}

sub is_ipv6 {
    my $addr = shift;
    return (defined inet_pton(AF_INET6, $addr)) ? 1 : 0;
}

sub conv_id {
    my $peer = shift;
    if (   is_ipv4($peer)
        || is_ipv6($peer) )
    {
        $peer = $peer;
    }
    elsif ( $peer =~ /\%any/ ) {
        $peer = "any";
    }
    else {
        $peer = "\@$peer";
    }
    return $peer;
}

#
# Convert stroke formatted [proto/port]
#
# Protocol must be in format of a well-known string:
#
# - to distinguish between [$proto] and [$port]
#
# This is enforced by vyatta-validate-type.pl protocol by a tmplscripts.
#
sub conv_proto_port {
    my ($input) = @_;
    my ($proto, $port);

    if (defined($input) && $input ne '') {

       ($proto, $port) = $input =~ /\[([^\/]*)\/([^\/]*)\]/xm;
       die "protocol must be formatted as well-known string." if (defined($proto) && $proto =~ /^\d+$/xm);
       unless (defined($port)) {
           my ($value) = $input =~ /\[(.*)\]/xm;
           unless (defined(getprotobyname($value))) {
              $port = $value;
           } else {
              $proto = $value;
           }
       }

    }

    return ($proto ? $proto : 'all', $port ? $port : 'all');
}

#
# unify an array but keep order of elements
#
sub uniq {
    my @elements = @_;
    my %seen;
    return grep { !$seen{$_}++ } @elements;
}

sub ip_cmp {
    my ($a, $b) = @_;

    die "Missing argument(s)" unless (defined $a && defined $b);

    my $ab = inet_pton(AF_INET, $a) || inet_pton(AF_INET6, $a);
    my $bb = inet_pton(AF_INET, $b) || inet_pton(AF_INET6, $b);

    if (! defined $ab) {
        # if $a is a string but $b is an address, $b comes first
        return 1 if (defined $bb);
        # both are strings
        return $a cmp $b;
    } elsif (! defined $bb) {
        # $b is a string, but $a is an address, $a comes first
        return -1;
    }

    # to compare as bitstrings, must both be of same length (i.e. family)
    my $x = length($ab) <=> length($bb);

    # if they're not the same length, then the shorter (IPv4) one wins
    return $x if ($x != 0);

    # otherwise, they're the same length and can be compared as strings
    return $ab cmp $bb;
}

sub tnormal
{
    my ($num, $units) = @_;
    given ($units) {
        $num *= 86400 when ("days");
        $num *= 3600 when ("hours");
        $num *= 60 when ("minutes");
    }
    return $num;
}

sub decode_pem {
    my ($str) = @_;

    my ( $type, $data ) = $str =~ m/
^-----BEGIN ([^\n-]+)-----\n
(.*)
-----END [^\n-]+-----$
/xsm;

    $type =~ s/^\s+//;
    $data = decode_base64($data);
    return { type => $type, data => $data };
}

sub decode_pem_asn1 {
    my ($type, $data) = @_;
    my $asn = Convert::ASN1->new;

    given ($type) {
        when ('RSA PUBLIC KEY') {
            $asn->prepare(<<ASN1) or croak "prepare: ", $asn->error;
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,
    publicExponent    INTEGER
}
ASN1
        }
        when ('PRIVATE KEY') {
            $asn->prepare(<<ASN1) or croak "prepare: ", $asn->error;
PrivateKeyInfo ::= SEQUENCE {
  version         Version,
  algorithm       AlgorithmIdentifier,
  PrivateKey      OCTET STRING
}

Version ::= INTEGER

AlgorithmIdentifier ::= SEQUENCE {
  algorithm       OBJECT IDENTIFIER,
  parameters      ANY DEFINED BY algorithm OPTIONAL
}
ASN1
            $asn = $asn->find("PrivateKeyInfo");
        }
        when ('PUBLIC KEY') {
            $asn->prepare(<<ASN1) or croak "prepare: ", $asn->error;
PublicKeyInfo ::= SEQUENCE {
  algorithm       AlgorithmIdentifier,
  PublicKey       BIT STRING
}
AlgorithmIdentifier ::= SEQUENCE {
  algorithm       OBJECT IDENTIFIER,
  parameters      ANY DEFINED BY algorithm OPTIONAL
}
ASN1
            $asn = $asn->find("PublicKeyInfo");
        }
        default {
            croak "decode: unsupported type \"$type\"\n";
        }
    }

    my $result = $asn->decode($data) or croak "decode: ", $asn->error();
    return $result;
}

sub get_pki_key_type {
    my ($file) = @_;
    my $lines = read_file($file, err_mode => 'quiet', binmode => ':raw' );

    return unless (defined $lines);

    return 'RAW' if $lines =~ m/^\s+\#pubkey=(\S+)$/xsm;

    # if we don't find the PEM start it migh be DER encoded
    if ($lines !~ m/^-----BEGIN/xsm) {
        my $pid = open2(my $CHLD_OUT, my $CHLD_IN, 'openssl pkey -inform DER')
            or die "open3() failed $!";
        write_file( $CHLD_IN, {binmode => ':raw'}, $lines ) ;
        close($CHLD_IN);
        $lines = read_file( $CHLD_OUT, err_mode => 'quiet' );
        close($CHLD_OUT);
    }

    my $asn = decode_pem($lines);

    return 'RSA' if $asn->{type} =~ /RSA/;
    return 'ECDSA' if $asn->{type} =~ /EC/;

    my $result = decode_pem_asn1($asn->{type}, $asn->{data});
    if (exists $result->{algorithm}) {

        given ($result->{algorithm}->{algorithm}) {
            when ('1.2.840.113549.1.1.1') {
                return 'RSA';
            }
            when ('1.2.840.10045.2.1') {
                return 'ECDSA';
            }
            default {
                croak $result->{algorithm}->{algorithm};
            }
        }
    }

    return;
}


###############################################################################

=item rsa_key_from_raw_key

This function returns the RSA private key part for the @file given. The
input file format is the RAW format.

=cut

###############################################################################
sub rsa_key_from_raw_key {
    my ($file) = @_;
    my %keyparam;

    my @lines = read_file($file);

    croak "empty file" unless @lines;

    foreach my $line (@lines) {
        next if $line =~ /^[\t\s]*#/;
        my ($key, $value) = $line =~ m/^[\t\s]+(\S+):\ 0x(\S+)$/xsm;
        next unless defined $key;
        $keyparam{$key} = $value;
    }

    croak "data not in RAW format" unless %keyparam;

    my $e = Crypt::OpenSSL::Bignum->new_from_hex($keyparam{PublicExponent});
    my $n = Crypt::OpenSSL::Bignum->new_from_hex($keyparam{Modulus});
    my $d = Crypt::OpenSSL::Bignum->new_from_hex($keyparam{PrivateExponent});
    my $p = Crypt::OpenSSL::Bignum->new_from_hex($keyparam{Prime1});
    my $q = Crypt::OpenSSL::Bignum->new_from_hex($keyparam{Prime2});

    return Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e, $d, $p, $q);
}

sub vpn_die {
  my (@path, $msg) = @_;
  Vyatta::Config::outputError(@path, $msg);
  exit 1;
}

sub vpn_exec {
  my ( $command, $desc ) = @_;

  open my $logf, '>>', $LOGFILE
    or die "Can't open $LOGFILE: $!";

  use POSIX;
  my $timestamp = strftime( "%Y-%m-%d %H:%M.%S", localtime );

  print ${logf} "$timestamp\nExecuting: $command\nDescription: $desc\n";

  my $cmd_out = qx($command);
  my $rval    = ( $? >> 8 );
  print ${logf} "Output:\n$cmd_out\n---\n";
  print ${logf} "Return code: $rval\n";
  if ($rval) {
    if ( $command =~ /^ipsec.*--asynchronous$/
      && ( $rval == 104 || $rval == 29 ) )
    {
      print ${logf} "OK when bringing up VPN connection\n";
    } else {

        #
        # We use to consider the commit failed if we got a error
        # from the call to ipsec, but this causes the configuration
        # to not get included in the running config.  Now that
        # we support dynamic interface/address (e.g. dhcp, pppoe)
        # we want a valid config to get committed even if the
        # interface doesn't exist yet.  That way we can use
        # "clear vpn ipsec-process" to bring up the tunnel once
        # the interface is instantiated.  For pppoe we will add
        # a script to /etc/ppp/ip-up.d to bring up the vpn
        # tunnel.
        #
      print ${logf}
        "VPN commit error.  Unable to $desc, received error code $?\n";
      #
      # code 768 is for a syntax error in the secrets file
      # this happens when a dhcp interface is configured
      # but no address is assigned yet.
      # only the line that has the syntax error is not loaded
      # So we can safely ignore this error since our code generates
      # secrets file.
      #
      if ($? ne '768'){
        print "Warning: unable to [$desc], received error code $?\n";
        print "$cmd_out\n";
      }
    }
  }
  print ${logf} "---\n\n";
  close $logf;

  return;
}

sub vpn_log {
  my ($log) = @_;

  open my $logfile, '>>', $LOGFILE
    or die "Can't open $LOGFILE: $!";

  use POSIX;
  my $timestamp = strftime( "%Y-%m-%d %H:%M.%S", localtime );

  print ${logfile} "$timestamp\n$log\n";
  print ${logfile} "---\n\n";
  close $logfile;

  return;
}

# Handle interface names from iproute2 output
#
# Bonded interfaces:
# dp0bond0.2000@dp0bond0 -> dp0bond0.2000
# dp0vrrp1@dp0bond1 -> dp0vrrp1
#
sub conv_intf {
  my ($intf) = @_;
  $intf =~ s/@.*//;

  return $intf;
}

sub get_intf {
  my ($addr) = @_;
  my $intf;

  $intf = `ip addr show | fgrep -B2 "inet $addr/" | head -n1 | awk '{print \$2}' | sed s/://`;
  return conv_intf($intf);
}

1;
