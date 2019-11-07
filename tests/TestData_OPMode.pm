# Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2007-2017 by Brocade Communications Systems, Inc.
# All rights reserved.
package TestData_OPMode;

# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use base qw(Exporter);

our @EXPORT_OK = qw(%TUNNEL_DEFAULTS);

our @EXPORT = qw(@pluto_ipsec_statusall_down_down @pluto_ipsec_statusall_init_down
                 @pluto_ipsec_statusall_up_down @pluto_ipsec_statusall_up_up
                 @pluto_ipsec_statusall_matcher_test @charon_ipsec_statusall_matcher_test
                 @charon_ipsec_statusall_down_down @charon_ipsec_statusall_init_down
                 @charon_ipsec_statusall_up_down @charon_ipsec_statusall_up_up
                 @charon_ipsec_statusall_vti_up_up @charon_ipsec_statusall_dhgroup
                 @charon_ipsec_statusall_nat @charon_ipsec_statusall_two_tunnels
                 @charon_ipsec_statusall_two_tunnels_one_down
                 @charon_ipsec_statusall_routed_connections
                 @charon_ipsec_statusall_shunted_connections
                 @charon_ipsec_statusall_auth_x509_remote_id_dn
                 @charon_ipsec_statusall_5_3_0_alloc_reqid
                 @charon_ipsec_statusall_up_up_aes256gcm128 
                 @charon_ipsec_statusall_up_up_aes_pfs_ECP
                 @charon_ipsec_statusall_proto_port
                 @charon_ipsec_statusall_esp_aes_gcm
                 @ip_xfrm_state_list_spi_unused @ip_xfrm_state_list_spi
                 @ipsec_conf_snippet 
                 @vplsh_ipsec_sad @vplsh_ipsec_sad_blocked
                 @charon_ipsec_statusall_hub_leftovers);

our %TUNNEL_DEFAULTS = (
  _peerid     => undef,
  _tunnelnum  => undef,
  _lip        => 'n/a',
  _rip        => 'n/a',
  _lid        => 'n/a',
  _rid        => 'n/a',
  _lsnet      => 'n/a',
  _rsnet      => 'n/a',
  _lproto     => 'all',
  _rproto     => 'all',
  _lport      => 'all',
  _rport      => 'all',
  _lca        => undef,
  _rca        => undef,
  _newestspi  => 'n/a',
  _reqid      => 'n/a',
  _newestike  => 'n/a',
  _encryption => 'n/a',
  _hash       => 'n/a',
  _inspi      => 'n/a',
  _outspi     => 'n/a',
  _pfsgrp     => 'n/a',
  _ikeencrypt => 'n/a',
  _ikehash    => 'n/a',
  _natt       => 'n/a',
  _natsrc     => 'n/a',
  _natdst     => 'n/a',
  _ikestate   => "down",
  _dhgrp      => 'n/a',
  _state      => undef,
  _inbytes    => 'n/a',
  _outbytes   => 'n/a',
  _ikelife    => 'n/a',
  _ikeexpire  => 'n/a',
  _lifetime   => 'n/a',
  _atime      => 'n/a'
);

#
# Data takes from https://www.strongswan.org/uml/pluto_charon_ikev1_interoperability/ikev1-p-c/net2net-psk-fail/index.html
#

# Note that this splits the here document into an array of strings (per line)
our @pluto_ipsec_statusall_down_down = <<'EOF' =~ m/(^.*$)/mg;
000 Status of IKEv1 pluto daemon (strongSwan 5.0.0dr1):
000 interface eth1/eth1 fec1::1:500
000 interface eth0/eth0 fec0::1:500
000 interface lo/lo ::1:500
000 interface lo/lo 127.0.0.1:500
000 interface eth0/eth0 192.168.0.1:500
000 interface eth1/eth1 10.1.0.1:500
000 %myid = '%any'
000 loaded plugins: sha1 sha2 md5 aes des hmac gmp random nonce kernel-netlink
000 debug options: control
000 
000 "peer-192.168.0.2-tunnel-1": 10.1.0.0/16===192.168.0.1[moon.strongswan.org]...192.168.0.2[sun.strongswan.org]===10.2.0.0/16; unrouted; eroute owner: #0
000 "peer-192.168.0.2-tunnel-1":   ike_life: 3600s; ipsec_life: 1200s; rekey_margin: 180s; rekey_fuzz: 100%; keyingtries: 1
000 "peer-192.168.0.2-tunnel-1":   policy: PSK+ENCRYPT+TUNNEL+UP; prio: 16,16; interface: eth0; 
000 "peer-192.168.0.2-tunnel-1":   newest ISAKMP SA: #0; newest IPsec SA: #0; 
000 
EOF

# Note that this splits the here document into an array of strings (per line)
our @pluto_ipsec_statusall_init_down = <<'EOF' =~ m/(^.*$)/mg;
000 Status of IKEv1 pluto daemon (strongSwan 4.5.2):
000 interface lo/lo ::1:500
000 interface lo/lo 127.0.0.1:500
000 interface dp0s7/dp0s7 192.168.40.6:500
000 interface dp0s8/dp0s8 192.168.100.6:500
000 %myid = '%any'
000 loaded plugins: test-vectors curl ldap aes des sha1 sha2 md5 random x509 pkcs1 pgp dnskey pem openssl gmp hmac xauth attr kernel-netlink resolve 
000 debug options: control
000 
000 "peer-192.168.100.7-tunnel-1": 192.168.40.0/24===192.168.100.6[192.168.100.6]...192.168.100.7[192.168.100.7]===192.168.248.0/24; unrouted; eroute owner: #0
000 "peer-192.168.100.7-tunnel-1":   ike_life: 28800s; ipsec_life: 3600s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0
000 "peer-192.168.100.7-tunnel-1":   policy: PSK+ENCRYPT+TUNNEL+UP; prio: 24,24; interface: dp0s8; 
000 "peer-192.168.100.7-tunnel-1":   newest ISAKMP SA: #0; newest IPsec SA: #0; 
000 
000 #21: "peer-192.168.100.7-tunnel-1" STATE_MAIN_I1 (sent MI1, expecting MR1); EVENT_RETRANSMIT in -39893s
000 #21: pending Phase 2 for "peer-192.168.100.7-tunnel-1" replacing #0
000 
EOF

# Note that this splits the here document into an array of strings (per line)
our @pluto_ipsec_statusall_up_down = <<'EOF' =~ m/(^.*$)/mg;
000 Status of IKEv1 pluto daemon (strongSwan 4.5.2):
000 interface lo/lo ::1:500
000 interface lo/lo 127.0.0.1:500
000 interface dp0s3/dp0s3 192.168.100.129:500
000 %myid = '%any'
000 loaded plugins: test-vectors curl ldap aes des sha1 sha2 md5 random x509 pkcs1 pgp dnskey pem openssl gmp hmac xauth attr kernel-netlink resolve 
000 debug options: raw+crypt+parsing+emitting+control+lifecycle+kernel+dns+natt+oppo+controlmore
000 
000 "peer-192.168.100.128-tunnel-1": 192.168.102.0/24===192.168.100.129[192.168.100.129]...192.168.100.128[192.168.100.128]===192.168.101.0/24; unrouted; eroute owner: #0
000 "peer-192.168.100.128-tunnel-1":   ike_life: 28800s; ipsec_life: 3600s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0
000 "peer-192.168.100.128-tunnel-1":   policy: PSK+ENCRYPT+TUNNEL+UP; prio: 24,24; interface: dp0s3; 
000 "peer-192.168.100.128-tunnel-1":   newest ISAKMP SA: #3; newest IPsec SA: #0; 
000 "peer-192.168.100.128-tunnel-1":   IKE proposal: AES_CBC_256/HMAC_SHA1/MODP_1536
000 
000 #3: "peer-192.168.100.128-tunnel-1" STATE_MAIN_R3 (sent MR3, ISAKMP SA established); EVENT_SA_REPLACE in 3315s; newest ISAKMP
000 #2: "peer-192.168.100.128-tunnel-1" STATE_QUICK_I1 (sent QI1, expecting QR1); EVENT_RETRANSMIT in 32s
000 #1: "peer-192.168.100.128-tunnel-1" STATE_MAIN_I4 (ISAKMP SA established); EVENT_SA_REPLACE in 27769s
000 
EOF

# Note that this splits the here document into an array of strings (per line)
our @pluto_ipsec_statusall_up_up = <<'EOF' =~ m/(^.*$)/mg;
000 Status of IKEv1 pluto daemon (strongSwan 4.5.2):
000 interface lo/lo ::1:500
000 interface lo/lo 127.0.0.1:500
000 interface dp0s3/dp0s3 192.168.100.129:500
000 %myid = '%any'
000 loaded plugins: test-vectors curl ldap aes des sha1 sha2 md5 random x509 pkcs1 pgp dnskey pem openssl gmp hmac xauth attr kernel-netlink resolve 
000 debug options: raw+crypt+parsing+emitting+control+lifecycle+kernel+dns+natt+oppo+controlmore
000 
000 "peer-192.168.100.128-tunnel-1": 192.168.102.0/24===192.168.100.129[192.168.100.129]...192.168.100.128[192.168.100.128]===192.168.101.0/24; erouted; eroute owner: #4
000 "peer-192.168.100.128-tunnel-1":   ike_life: 28800s; ipsec_life: 3600s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0
000 "peer-192.168.100.128-tunnel-1":   policy: PSK+ENCRYPT+TUNNEL+UP; prio: 24,24; interface: dp0s3; 
000 "peer-192.168.100.128-tunnel-1":   newest ISAKMP SA: #3; newest IPsec SA: #4; 
000 "peer-192.168.100.128-tunnel-1":   IKE proposal: AES_CBC_256/HMAC_SHA1/MODP_1536
000 "peer-192.168.100.128-tunnel-1":   ESP proposal: AES_CBC_256/HMAC_SHA1/<N/A>
000 
000 #1: "peer-192.168.100.128-tunnel-1" STATE_MAIN_I4 (ISAKMP SA established); EVENT_SA_REPLACE in 27674s
000 #4: "peer-192.168.100.128-tunnel-1" STATE_QUICK_I2 (sent QI2, IPsec SA established); EVENT_SA_REPLACE in 2785s; newest IPSEC; eroute owner
000 #4: "peer-192.168.100.128-tunnel-1" esp.c61fd7e2@192.168.100.128 (0 bytes) esp.c5e524d9@192.168.100.129 (0 bytes); tunnel
000 #3: "peer-192.168.100.128-tunnel-1" STATE_MAIN_R3 (sent MR3, ISAKMP SA established); EVENT_SA_REPLACE in 3198s; newest ISAKMP
000 
EOF

our @pluto_ipsec_statusall_matcher_test = <<'EOF' =~ m/(^.*$)/mg;
000 "peer-192.168.0.2-tunnel-1": 10.2.0.0/16===192.168.0.2[sun.strongswan.org]...%any[%any]==={10.1.0.0/16}; unrouted; eroute owner: #0
000 "peer-192.168.0.2-tunnel-1"[2]: 10.2.0.0/16===192.168.0.2:4500[sun.strongswan.org]...192.168.0.1:1025[alice@strongswan.org]===10.1.0.10/32; erouted; eroute owner: #2
000 "peer-192.168.0.2-tunnel-1"[4]: 10.2.0.0/16===192.168.0.2:4500[sun.strongswan.org]...192.168.0.1:1026[venus.strongswan.org]===10.1.0.20/32; erouted; eroute owner: #4
000 #2: "peer-192.168.0.2-tunnel-1"[2] 192.168.0.1:1025 STATE_QUICK_R2 (IPsec SA established); EVENT_SA_REPLACE in 1090s; newest IPSEC; eroute owner
000 #4: "peer-192.168.0.2-tunnel-1"[4] 192.168.0.1:1026 STATE_QUICK_R2 (IPsec SA established); EVENT_SA_REPLACE in 1094s; newest IPSEC; eroute owner
EOF

our @charon_ipsec_statusall_matcher_test = <<'EOF' =~ m/(^.*$)/mg;
peer-192.168.100.6-tunnel-1:  192.168.100.7...192.168.100.6  IKEv1
peer-192.168.100.6-tunnel-1[1]: ESTABLISHED 105 minutes ago, 192.168.100.7[192.168.100.7]...192.168.100.6[192.168.100.6]
peer-192.168.100.6-tunnel-1{2}:  REKEYING, TUNNEL, expires in 114 seconds
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_down_down = << 'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 3.14.34-1-amd64-vyatta, x86_64):
  uptime: 8 minutes, since Apr 27 15:22:25 2015
  malloc: sbrk 675840, mmap 0, used 573600, free 102240
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors ldap pkcs11 aes rc2 sha1 sha2 md5 rdrand random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl gcrypt af-alg fips-prf gmp agent xcbc cmac hmac ctr ccm gcm curl attr kernel-netlink resolve socket-default farp stroke updown eap-identity eap-aka eap-md5 eap-gtc eap-mschapv2 eap-radius eap-tls eap-ttls eap-tnc xauth-generic xauth-eap xauth-pam tnc-tnccs dhcp lookip error-notify certexpire led addrblock unity
Listening IP addresses:
  192.168.100.7
  192.168.248.7
Connections:
peer-192.168.100.6-tunnel-1:  192.168.100.7...192.168.100.6  IKEv1
peer-192.168.100.6-tunnel-1:   local:  [192.168.100.7] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   remote: [192.168.100.6] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   child:  192.168.248.0/24 === 192.168.40.0/24 TUNNEL
Security Associations (0 up, 0 connecting):
  none
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_init_down = << 'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 3.14.34-1-amd64-vyatta, x86_64):
  uptime: 79 seconds, since Apr 28 08:56:23 2015
  malloc: sbrk 675840, mmap 0, used 580240, free 95600
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 1
  loaded plugins: charon test-vectors ldap pkcs11 aes rc2 sha1 sha2 md5 rdrand random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl gcrypt af-alg fips-prf gmp agent xcbc cmac hmac ctr ccm gcm curl attr kernel-netlink resolve socket-default farp stroke updown eap-identity eap-aka eap-md5 eap-gtc eap-mschapv2 eap-radius eap-tls eap-ttls eap-tnc xauth-generic xauth-eap xauth-pam tnc-tnccs dhcp lookip error-notify certexpire led addrblock unity
Listening IP addresses:
  192.168.100.7
  192.168.248.7
Connections:
peer-192.168.100.6-tunnel-1:  192.168.100.7...192.168.100.6  IKEv1
peer-192.168.100.6-tunnel-1:   local:  [192.168.100.7] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   remote: [192.168.100.6] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   child:  192.168.248.0/24 === 192.168.40.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-192.168.100.6-tunnel-1[1]: CONNECTING, 192.168.100.7[%any]...192.168.100.6[%any]
peer-192.168.100.6-tunnel-1[1]: IKEv1 SPIs: cbbafc95affa94fc_i* 0000000000000000_r
peer-192.168.100.6-tunnel-1[1]: Tasks queued: QUICK_MODE 
peer-192.168.100.6-tunnel-1[1]: Tasks active: ISAKMP_VENDOR ISAKMP_CERT_PRE MAIN_MODE ISAKMP_CERT_POST ISAKMP_NATD 
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_up_down = << 'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 3.14.34-1-amd64-vyatta, x86_64):
  uptime: 4 minutes, since Apr 08 12:39:20 2015
  malloc: sbrk 663552, mmap 0, used 578592, free 84960
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 7
  loaded plugins: charon test-vectors ldap pkcs11 aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl gcrypt af-alg fips-prf gmp agent xcbc cmac hmac ctr ccm gcm curl attr kernel-netlink resolve socket-default farp stroke updown eap-identity eap-aka eap-md5 eap-gtc eap-mschapv2 eap-radius eap-tls eap-ttls eap-tnc xauth-generic xauth-eap xauth-pam tnc-tnccs dhcp lookip error-notify certexpire led addrblock unity
Listening IP addresses:
  192.168.100.128
Connections:
peer-192.168.100.129-tunnel-1:  192.168.100.128...192.168.100.129  IKEv1
peer-192.168.100.129-tunnel-1:   local:  [192.168.100.128] uses pre-shared key authentication
peer-192.168.100.129-tunnel-1:   remote: [192.168.100.129] uses pre-shared key authentication
peer-192.168.100.129-tunnel-1:   child:  192.168.101.0/24 === 192.168.102.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-192.168.100.129-tunnel-1[3]: ESTABLISHED 7 seconds ago, 192.168.100.128[192.168.100.128]...192.168.100.129[192.168.100.129]
peer-192.168.100.129-tunnel-1[3]: IKEv1 SPIs: 8cec46b9eec6766a_i* 624b9b54d221f51e_r, pre-shared key reauthentication in 44 minutes
peer-192.168.100.129-tunnel-1[3]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-192.168.100.129-tunnel-1[3]: Tasks queued: QUICK_MODE 
peer-192.168.100.129-tunnel-1[3]: Tasks active: MODE_CONFIG 
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_up_up = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 3.14.34-1-amd64-vyatta, x86_64):
  uptime: 2 hours, since Apr 28 12:27:39 2015
  malloc: sbrk 675840, mmap 0, used 595904, free 79936
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors ldap pkcs11 aes rc2 sha1 sha2 md5 rdrand random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl gcrypt af-alg fips-prf gmp agent xcbc cmac hmac ctr ccm gcm curl attr kernel-netlink resolve socket-default farp stroke updown eap-identity eap-aka eap-md5 eap-gtc eap-mschapv2 eap-radius eap-tls eap-ttls eap-tnc xauth-generic xauth-eap xauth-pam tnc-tnccs dhcp lookip error-notify certexpire led addrblock unity
Listening IP addresses:
  192.168.100.7
  192.168.248.7
Connections:
peer-192.168.100.6-tunnel-1:  192.168.100.7...192.168.100.6  IKEv1
peer-192.168.100.6-tunnel-1:   local:  [192.168.100.7] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   remote: [192.168.100.6] uses pre-shared key authentication
peer-192.168.100.6-tunnel-1:   child:  192.168.248.0/24 === 192.168.40.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-192.168.100.6-tunnel-1[11]: ESTABLISHED 105 minutes ago, 192.168.100.7[192.168.100.7]...192.168.100.6[192.168.100.6]
peer-192.168.100.6-tunnel-1[11]: IKEv1 SPIs: fd5e506d4aab3722_i* 85ac2701e84055d1_r, pre-shared key reauthentication in 5 hours
peer-192.168.100.6-tunnel-1[11]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-192.168.100.6-tunnel-1{21}:  REKEYING, TUNNEL, expires in 114 seconds
peer-192.168.100.6-tunnel-1{21}:   192.168.248.0/24 === 192.168.40.0/24 
peer-192.168.100.6-tunnel-1{21}:  INSTALLED, TUNNEL, ESP SPIs: cc436578_i c74a030d_o
peer-192.168.100.6-tunnel-1{21}:  AES_CBC_256/HMAC_SHA1_96, 336 bytes_i (4 pkts, 2s ago), 336 bytes_o (4 pkts, 2s ago), rekeying in 15 minutes
peer-192.168.100.6-tunnel-1{21}:   192.168.248.0/24 === 192.168.40.0/24 
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_vti_up_up = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.1.6-1-amd64-vyatta, x86_64):
  uptime: 2 hours, since Sep 09 13:24:27 2015
  malloc: sbrk 2408448, mmap 0, used 343360, free 2065088
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 3
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  192.168.248.236
  21.1.0.1
Connections:
peer-192.168.248.248-tunnel-vti:  192.168.248.236...192.168.248.248  IKEv1
peer-192.168.248.248-tunnel-vti:   local:  [192.168.248.236] uses pre-shared key authentication
peer-192.168.248.248-tunnel-vti:   remote: [192.168.248.248] uses pre-shared key authentication
peer-192.168.248.248-tunnel-vti:   child:  0.0.0.0/0 === 0.0.0.0/0 TUNNEL
Security Associations (1 up, 0 connecting):
peer-192.168.248.248-tunnel-vti[345]: ESTABLISHED 29 seconds ago, 192.168.248.236[192.168.248.236]...192.168.248.248[192.168.248.248]
peer-192.168.248.248-tunnel-vti[345]: IKEv1 SPIs: 9576650459cfd7f1_i* c577fdf952d51326_r, pre-shared key reauthentication in 3 minutes
peer-192.168.248.248-tunnel-vti[345]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-192.168.248.248-tunnel-vti{1}:  REKEYED, TUNNEL, expires in 27 seconds
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
peer-192.168.248.248-tunnel-vti{1}:  REKEYED, TUNNEL, expires in 39 seconds
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
peer-192.168.248.248-tunnel-vti{1}:  INSTALLED, TUNNEL, ESP SPIs: c965452c_i c74a030d_o
peer-192.168.248.248-tunnel-vti{1}:  AES_CBC_256/HMAC_SHA1_96, 12445020 bytes_i (8715 pkts, 0s ago), 12446448 bytes_o (8716 pkts, 0s ago), rekeying in 1 second
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
EOF

our @charon_ipsec_statusall_nat = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.1.14-1-amd64-vyatta, x86_64):
  uptime: 14 minutes, since Dec 16 17:05:03 2015
  malloc: sbrk 2547712, mmap 0, used 336192, free 2211520
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 0
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  172.27.246.101
  190.160.2.1
  190.160.1.2
Connections:
peer-0.0.0.0-tunnel-1:  190.160.2.1...%any  IKEv1
peer-0.0.0.0-tunnel-1:   local:  [190.160.2.1] uses pre-shared key authentication
peer-0.0.0.0-tunnel-1:   remote: uses pre-shared key authentication
peer-0.0.0.0-tunnel-1:   child:  190.160.1.0/24 === 190.160.4.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-0.0.0.0-tunnel-1[1]: ESTABLISHED 14 minutes ago, 190.160.2.1[500][190.160.2.1]...190.160.5.2[500][190.160.3.2]
peer-0.0.0.0-tunnel-1[1]: IKEv1 SPIs: d721cf8c7eaa22f4_i 1eab9a0f09f97cc4_r*, rekeying disabled
peer-0.0.0.0-tunnel-1[1]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-0.0.0.0-tunnel-1{1}:  INSTALLED, TUNNEL, ESP in UDP SPIs: c965452c_i c74a030d_o
peer-0.0.0.0-tunnel-1{1}:  AES_CBC_256/HMAC_MD5_96, 0 bytes_i, 0 bytes_o, rekeying disabled
peer-0.0.0.0-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
EOF

# Note that this splits the here document into an array of strings (per line)
our @charon_ipsec_statusall_dhgroup = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.1.6-1-amd64-vyatta, x86_64):
  uptime: 2 hours, since Sep 09 13:24:27 2015
  malloc: sbrk 2408448, mmap 0, used 343360, free 2065088
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 3
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  192.168.248.236
  21.1.0.1
Connections:
peer-192.168.248.248-tunnel-vti:  192.168.248.236...192.168.248.248  IKEv1
peer-192.168.248.248-tunnel-vti:   local:  [192.168.248.236] uses pre-shared key authentication
peer-192.168.248.248-tunnel-vti:   remote: [192.168.248.248] uses pre-shared key authentication
peer-192.168.248.248-tunnel-vti:   child:  0.0.0.0/0 === 0.0.0.0/0 TUNNEL
Security Associations (1 up, 0 connecting):
peer-192.168.248.248-tunnel-vti[345]: ESTABLISHED 29 seconds ago, 192.168.248.236[192.168.248.236]...192.168.248.248[192.168.248.248]
peer-192.168.248.248-tunnel-vti[345]: IKEv1 SPIs: 9576650459cfd7f1_i* c577fdf952d51326_r, pre-shared key reauthentication in 3 minutes
peer-192.168.248.248-tunnel-vti[345]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-192.168.248.248-tunnel-vti{1}:  REKEYED, TUNNEL, expires in 27 seconds
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
peer-192.168.248.248-tunnel-vti{1}:  REKEYED, TUNNEL, expires in 39 seconds
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
peer-192.168.248.248-tunnel-vti{1}:  INSTALLED, TUNNEL, ESP SPIs: c965452c_i c74a030d_o
peer-192.168.248.248-tunnel-vti{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1024, 12445020 bytes_i (8715 pkts, 0s ago), 12446448 bytes_o (8716 pkts, 0s ago), rekeying in 1 second
peer-192.168.248.248-tunnel-vti{1}:   0.0.0.0/0 === 0.0.0.0/0 
EOF

our @charon_ipsec_statusall_two_tunnels = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.4.0-rc8-amd64-vyatta, x86_64):
  uptime: 15 minutes, since Jan 06 15:42:00 2016
  malloc: sbrk 2547712, mmap 0, used 357664, free 2190048
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  172.27.246.101
  190.160.2.1
  190.160.10.2
  190.160.1.2
Connections:
peer-190.160.3.2-tunnel-1:  190.160.2.1...190.160.3.2  IKEv1
peer-190.160.3.2-tunnel-1:   local:  [190.160.2.1] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   remote: [190.160.3.2] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   child:  190.160.1.0/24 === 190.160.4.0/24 TUNNEL
peer-190.160.3.2-tunnel-2:   child:  190.160.10.0/24 === 190.160.40.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-190.160.3.2-tunnel-1[2]: ESTABLISHED 14 minutes ago, 190.160.2.1[190.160.2.1]...190.160.3.2[190.160.3.2]
peer-190.160.3.2-tunnel-1[2]: IKEv1 SPIs: 20a2515aaccf47d6_i 409a2d0efc421a47_r*, pre-shared key reauthentication in 36 minutes
peer-190.160.3.2-tunnel-1[2]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
peer-190.160.3.2-tunnel-1{1}:  REKEYED, TUNNEL, expires in 14 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
peer-190.160.3.2-tunnel-2{2}:  INSTALLED, TUNNEL, ESP SPIs: c53a2af9_i c6c6150d_o
peer-190.160.3.2-tunnel-2{2}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 27 minutes
peer-190.160.3.2-tunnel-2{2}:   190.160.10.0/24 === 190.160.40.0/24
peer-190.160.3.2-tunnel-1{1}:  REKEYED, TUNNEL, expires in 15 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
peer-190.160.3.2-tunnel-1{1}:  INSTALLED, TUNNEL, ESP SPIs: cd4c780f_i c5d8bacf_o
peer-190.160.3.2-tunnel-1{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 12 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
EOF

our @charon_ipsec_statusall_two_tunnels_one_down = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.4.0-rc8-amd64-vyatta, x86_64):
  uptime: 15 minutes, since Jan 06 15:42:00 2016
  malloc: sbrk 2547712, mmap 0, used 357664, free 2190048
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  172.27.246.101
  190.160.2.1
  190.160.10.2
  190.160.1.2
Connections:
peer-190.160.3.2-tunnel-1:  190.160.2.1...190.160.3.2  IKEv1
peer-190.160.3.2-tunnel-1:   local:  [190.160.2.1] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   remote: [190.160.3.2] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   child:  190.160.1.0/24 === 190.160.4.0/24 TUNNEL
peer-190.160.3.2-tunnel-2:   child:  190.160.10.0/24 === 190.160.40.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-190.160.3.2-tunnel-1[2]: ESTABLISHED 14 minutes ago, 190.160.2.1[190.160.2.1]...190.160.3.2[190.160.3.2]
peer-190.160.3.2-tunnel-1[2]: IKEv1 SPIs: 20a2515aaccf47d6_i 409a2d0efc421a47_r*, pre-shared key reauthentication in 36 minutes
peer-190.160.3.2-tunnel-1[2]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
peer-190.160.3.2-tunnel-1{1}:  REKEYED, TUNNEL, expires in 14 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
peer-190.160.3.2-tunnel-1{1}:  REKEYED, TUNNEL, expires in 15 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
peer-190.160.3.2-tunnel-1{1}:  INSTALLED, TUNNEL, ESP SPIs: cd4c780f_i c5d8bacf_o
peer-190.160.3.2-tunnel-1{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 12 minutes
peer-190.160.3.2-tunnel-1{1}:   190.160.1.0/24 === 190.160.4.0/24
EOF

our @charon_ipsec_statusall_routed_connections = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.3-1-amd64-vyatta, x86_64):
  uptime: 23 minutes, since Mar 09 02:11:51 2016
  malloc: sbrk 2560000, mmap 0, used 405024, free 2154976
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 29
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  10.20.99.31
  192.0.71.1
  192.169.17.1
  192.0.7.1
Connections:
peer-192.0.72.2-tunnel-vti:  192.0.71.1...192.0.72.2  IKEv2, dpddelay=30s
peer-192.0.72.2-tunnel-vti:   local:  [192.0.71.1] uses pre-shared key authentication
peer-192.0.72.2-tunnel-vti:   remote: [192.0.72.2] uses pre-shared key authentication
peer-192.0.72.2-tunnel-vti:   child:  0.0.0.0/0 === 0.0.0.0/0 TUNNEL, dpdaction=restart
Routed Connections:
peer-192.0.72.2-tunnel-vti{6}:  ROUTED, TUNNEL, reqid 3
peer-192.0.72.2-tunnel-vti{6}:   0.0.0.0/0 === 0.0.0.0/0
Security Associations (3 up, 0 connecting):
peer-192.0.72.2-tunnel-vti[13]: ESTABLISHED 58 seconds ago, 192.0.71.1[500][192.0.71.1]...192.0.72.2[500][192.0.72.2]
peer-192.0.72.2-tunnel-vti[13]: IKEv2 SPIs: 03fd578ffd1bbce0_i* 64ae2f1515807711_r, pre-shared key reauthentication in 23 hours
peer-192.0.72.2-tunnel-vti[13]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384
peer-192.0.72.2-tunnel-vti{14}:  INSTALLED, TUNNEL, reqid 3, ESP SPIs: c03991f6_i 0001dd51_o
peer-192.0.72.2-tunnel-vti{14}:  AES_GCM_16_128, 0 bytes_i, 0 bytes_o, rekeying in 7 hours
peer-192.0.72.2-tunnel-vti{14}:   0.0.0.0/0 === 0.0.0.0/0
peer-192.0.72.2-tunnel-vti[12]: ESTABLISHED 109 seconds ago, 192.0.71.1[500][192.0.71.1]...192.0.72.2[500][192.0.72.2]
peer-192.0.72.2-tunnel-vti[12]: IKEv2 SPIs: 5bfb2a3938bd801b_i* e0b710e4f1ea102e_r, pre-shared key reauthentication in 23 hours
peer-192.0.72.2-tunnel-vti[12]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384
peer-192.0.72.2-tunnel-vti{13}:  INSTALLED, TUNNEL, reqid 3, ESP SPIs: c9c56530_i 0001377b_o
peer-192.0.72.2-tunnel-vti{13}:  AES_GCM_16_128, 0 bytes_i, 0 bytes_o, rekeying in 7 hours
peer-192.0.72.2-tunnel-vti{13}:   0.0.0.0/0 === 0.0.0.0/0
peer-192.0.72.2-tunnel-vti[11]: ESTABLISHED 3 minutes ago, 192.0.71.1[500][192.0.71.1]...192.0.72.2[500][192.0.72.2]
peer-192.0.72.2-tunnel-vti[11]: IKEv2 SPIs: 5adf3d0f3b536af0_i* 6975e6079627a309_r, pre-shared key reauthentication in 23 hours
peer-192.0.72.2-tunnel-vti[11]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384
peer-192.0.72.2-tunnel-vti[11]: Tasks active: IKE_DPD
peer-192.0.72.2-tunnel-vti{12}:  INSTALLED, TUNNEL, reqid 3, ESP SPIs: cec3b69f_i 0001def5_o
peer-192.0.72.2-tunnel-vti{12}:  AES_GCM_16_128, 0 bytes_i, 0 bytes_o, rekeying in 7 hours
peer-192.0.72.2-tunnel-vti{12}:   0.0.0.0/0 === 0.0.0.0/0
EOF

our @charon_ipsec_statusall_shunted_connections = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.11-1-amd64-vyatta, x86_64):
  uptime: 47 seconds, since May 26 14:29:15 2016
  malloc: sbrk 2420736, mmap 0, used 386176, free 2034560
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 27
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  192.168.252.61
  10.10.1.2
  10.10.2.2
Connections:
peer-10.10.2.3-tunnel-1:  10.10.2.2...10.10.2.3  IKEv1
peer-10.10.2.3-tunnel-1:   local:  [10.10.2.2] uses pre-shared key authentication
peer-10.10.2.3-tunnel-1:   remote: [10.10.2.3] uses pre-shared key authentication
peer-10.10.2.3-tunnel-1:   child:  10.10.1.0/24 === 10.10.3.0/24 TUNNEL
shunt-peer-10.10.2.3-tunnel-1:  %any...%any  IKEv1
shunt-peer-10.10.2.3-tunnel-1:   local:  uses public key authentication
shunt-peer-10.10.2.3-tunnel-1:   remote: uses public key authentication
shunt-peer-10.10.2.3-tunnel-1:   child:  10.10.1.0/24 === 10.10.3.0/24 DROP
Shunted Connections:
shunt-peer-10.10.2.3-tunnel-1:  10.10.1.0/24 === 10.10.3.0/24 DROP
Security Associations (4 up, 0 connecting):
peer-10.10.2.3-tunnel-1[6]: ESTABLISHED 1 second ago, 10.10.2.2[500][10.10.2.2]...10.10.2.3[500][10.10.2.3]
peer-10.10.2.3-tunnel-1[6]: IKEv1 SPIs: 1dbeddcacba5b0dc_i ac01f9847ddd19de_r*, pre-shared key reauthentication in 28 seconds
peer-10.10.2.3-tunnel-1[6]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-10.10.2.3-tunnel-1{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c3593216_i cf5b3aa3_o
peer-10.10.2.3-tunnel-1{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1536, 0 bytes_i, 0 bytes_o, rekeying in 3 minutes
peer-10.10.2.3-tunnel-1{1}:   10.10.1.0/24 === 10.10.3.0/24
peer-10.10.2.3-tunnel-1[5]: ESTABLISHED 2 seconds ago, 10.10.2.2[500][10.10.2.2]...10.10.2.3[500][10.10.2.3]
peer-10.10.2.3-tunnel-1[5]: IKEv1 SPIs: 65c448406e2deb42_i 7032b2c5585f35e0_r*, pre-shared key reauthentication in 14 seconds
peer-10.10.2.3-tunnel-1[5]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-10.10.2.3-tunnel-1[4]: ESTABLISHED 9 seconds ago, 10.10.2.2[500][10.10.2.2]...10.10.2.3[500][10.10.2.3]
peer-10.10.2.3-tunnel-1[4]: IKEv1 SPIs: 482425ad13127a55_i 969cf83fe15a956f_r*, pre-shared key reauthentication in 3 seconds
peer-10.10.2.3-tunnel-1[4]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-10.10.2.3-tunnel-1[3]: ESTABLISHED 11 seconds ago, 10.10.2.2[500][10.10.2.2]...10.10.2.3[500][10.10.2.3]
peer-10.10.2.3-tunnel-1[3]: IKEv1 SPIs: 01b0e27a1fc2e536_i* 62e89bf36481fadb_r, pre-shared key reauthentication in 6 seconds
peer-10.10.2.3-tunnel-1[3]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
EOF

our @charon_ipsec_statusall_auth_x509_remote_id_dn = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.1.6-1-amd64-vyatta, x86_64):
  uptime: 19 minutes, since Aug 21 15:44:13 2015
  malloc: sbrk 2412544, mmap 0, used 392848, free 2019696
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 5
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  172.27.242.218
  11::1
  11.1.0.1
  11:1::1
  11.2.0.1
  11:2::1
  192.168.1.1
  192:168::1:1
Connections:
peer-11.1.0.2-tunnel-1:  11.1.0.1...11.1.0.2  IKEv1
peer-11.1.0.2-tunnel-1:   local:  [C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain] uses public key authentication
peer-11.1.0.2-tunnel-1:    cert:  "C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain"
peer-11.1.0.2-tunnel-1:   remote: [C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Client, E=me@myhost.mydomain] uses public key authentication
peer-11.1.0.2-tunnel-1:   child:  192.168.1.1/32 === 192.168.1.2/32 TUNNEL
peer-11:1::2-tunnel-2:  11:1::1...11:1::2  IKEv1
peer-11:1::2-tunnel-2:   local:  [C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain] uses public key authentication
peer-11:1::2-tunnel-2:    cert:  "C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain"
peer-11:1::2-tunnel-2:   remote: [C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Client, E=me@myhost.mydomain] uses public key authentication
peer-11:1::2-tunnel-2:   child:  192:168::1:1/128 === 192:168::1:2/128 TUNNEL
Security Associations (2 up, 0 connecting):
peer-11:1::2-tunnel-2[2]: ESTABLISHED 19 minutes ago, 11:1::1[C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain]...11:1::2[C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Client, E=me@myhost.mydomain]
peer-11:1::2-tunnel-2[2]: IKEv1 SPIs: 3ea74bd57508f828_i* 340567729bc67e2c_r, public key reauthentication in 23 minutes
peer-11:1::2-tunnel-2[2]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-11:1::2-tunnel-2{1}:  INSTALLED, TUNNEL, ESP SPIs: cef879d2_i c3f6c7cc_o
peer-11:1::2-tunnel-2{1}:  AES_CBC_256/HMAC_SHA1_96, 0 bytes_i, 0 bytes_o, rekeying in 25 minutes
peer-11:1::2-tunnel-2{1}:   192:168::1:1/128 === 192:168::1:2/128 
peer-11.1.0.2-tunnel-1[1]: CONNECTING, 11.1.0.1[C=KG, ST=NA, O=OpenVPN-TEST, CN=Test-Server, E=me@myhost.mydomain]...11.1.0.2[%any]
peer-11.1.0.2-tunnel-1[1]: IKEv1 SPIs: 2b2b4ef94e8b58d7_i* 0694a583fc98a198_r
peer-11.1.0.2-tunnel-1[1]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
peer-11.1.0.2-tunnel-1[1]: Tasks queued: QUICK_MODE 
peer-11.1.0.2-tunnel-1[1]: Tasks active: ISAKMP_VENDOR ISAKMP_CERT_PRE MAIN_MODE 
EOF

our @charon_ipsec_statusall_5_3_0_alloc_reqid = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.2-1-amd64-vyatta, x86_64):
  uptime: 5 hours, since Mar 04 10:07:41 2016
  malloc: sbrk 2424832, mmap 0, used 368480, free 2056352
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 3
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  192.168.252.87
  10.10.2.3
  10.10.3.3
Connections:
peer-10.10.2.2-tunnel-1:  10.10.2.3...10.10.2.2  IKEv1
peer-10.10.2.2-tunnel-1:   local:  [10.10.2.3] uses pre-shared key authentication
peer-10.10.2.2-tunnel-1:   remote: [10.10.2.2] uses pre-shared key authentication
peer-10.10.2.2-tunnel-1:   child:  10.10.3.0/24 === 10.10.1.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-10.10.2.2-tunnel-1[558]: ESTABLISHED 17 seconds ago, 10.10.2.3[500][10.10.2.3]...10.10.2.2[500][10.10.2.2]
peer-10.10.2.2-tunnel-1[558]: IKEv1 SPIs: 16f5b675c016e57a_i* 2de02a49a02f4714_r, pre-shared key reauthentication in 28 seconds
peer-10.10.2.2-tunnel-1[558]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_2048
peer-10.10.2.2-tunnel-1{982}:  REKEYED, TUNNEL, reqid 6, expires in 13 seconds
peer-10.10.2.2-tunnel-1{982}:   10.10.3.0/24 === 10.10.1.0/24
peer-10.10.2.2-tunnel-1{983}:  REKEYED, TUNNEL, reqid 6, expires in 15 seconds
peer-10.10.2.2-tunnel-1{983}:   10.10.3.0/24 === 10.10.1.0/24
peer-10.10.2.2-tunnel-1{985}:  INSTALLED, TUNNEL, reqid 6, ESP SPIs: c5785964_i c9a19b97_o
peer-10.10.2.2-tunnel-1{985}:  AES_CBC_256/HMAC_SHA1_96/MODP_2048, 0 bytes_i, 0 bytes_o, rekeying in 3 seconds
peer-10.10.2.2-tunnel-1{985}:   10.10.3.0/24 === 10.10.1.0/24
peer-10.10.2.2-tunnel-1{986}:  INSTALLED, TUNNEL, reqid 6, ESP SPIs: c11192c8_i cb088a2b_o
peer-10.10.2.2-tunnel-1{986}:  AES_CBC_256/HMAC_SHA1_96/MODP_2048, 0 bytes_i, 0 bytes_o, rekeying in 0 seconds
peer-10.10.2.2-tunnel-1{986}:   10.10.3.0/24 === 10.10.1.0/24
EOF

our @charon_ipsec_statusall_up_up_aes256gcm128 = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.4.2-1-amd64-vyatta, x86_64):
  uptime: 2 hours, since Mar 04 18:36:37 2016
  malloc: sbrk 2408448, mmap 0, used 339232, free 2069216
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 21
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  192.168.252.92
  10.10.1.1
Connections:
peer-10.10.1.2-tunnel-1:  10.10.1.1...10.10.1.2  IKEv1
peer-10.10.1.2-tunnel-1:   local:  [10.10.1.1] uses pre-shared key authentication
peer-10.10.1.2-tunnel-1:   remote: [10.10.1.2] uses pre-shared key authentication
peer-10.10.1.2-tunnel-1:   child:  10.10.1.0/24 === 10.10.3.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-10.10.1.2-tunnel-1[10]: ESTABLISHED 13 seconds ago, 10.10.1.1[500][10.10.1.1]...10.10.1.2[500][10.10.1.2]
peer-10.10.1.2-tunnel-1[10]: IKEv1 SPIs: 42eb9cfb343cacf1_i 6b4ecee7cf3b0767_r*, pre-shared key reauthentication in 7 hours
peer-10.10.1.2-tunnel-1[10]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
peer-10.10.1.2-tunnel-1{8}:  INSTALLED, TUNNEL, ESP SPIs: c9a8db96_i c667b512_o
peer-10.10.1.2-tunnel-1{8}:  AES_GCM_16_256/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 49 minutes
peer-10.10.1.2-tunnel-1{8}:   10.10.1.0/24 === 10.10.3.0/24
EOF

our @charon_ipsec_statusall_up_up_aes_pfs_ECP = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.6-1-amd64-vyatta, x86_64):
  uptime: 36 minutes, since Mar 30 17:15:49 2016
  malloc: sbrk 2420736, mmap 0, used 348768, free 2071968
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 7
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  192.168.252.1
  10.10.1.2
Connections:
peer-10.10.1.1-tunnel-1:  10.10.1.2...10.10.1.1  IKEv1
peer-10.10.1.1-tunnel-1:   local:  [10.10.1.2] uses pre-shared key authentication
peer-10.10.1.1-tunnel-1:   remote: [10.10.1.1] uses pre-shared key authentication
peer-10.10.1.1-tunnel-1:   child:  10.10.3.0/24 === 10.10.4.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-10.10.1.1-tunnel-1[6]: ESTABLISHED 32 seconds ago, 10.10.1.2[500][10.10.1.2]...10.10.1.1[500][10.10.1.1]
peer-10.10.1.1-tunnel-1[6]: IKEv1 SPIs: 335c588928d25a14_i 8ff6419aaea9b656_r*, pre-shared key reauthentication in 7 hours
peer-10.10.1.1-tunnel-1[6]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_2048
peer-10.10.1.1-tunnel-1{3}:  INSTALLED, TUNNEL, reqid 2, ESP SPIs: c47c36fe_i c28acf7c_o
peer-10.10.1.1-tunnel-1{3}:  AES_GCM_16_128/ECP_256, 0 bytes_i, 0 bytes_o, rekeying in 43 minutes
peer-10.10.1.1-tunnel-1{3}:   10.10.3.0/24 === 10.10.4.0/24
EOF

our @charon_ipsec_statusall_proto_port = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.4-1-amd64-vyatta, x86_64):
  uptime: 29 minutes, since Mar 21 12:07:07 2016
  malloc: sbrk 2543616, mmap 0, used 371984, free 2171632
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 8
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  172.27.246.101
  190.160.2.1
  190.160.1.2
Connections:
peer-190.160.3.2-tunnel-1:  190.160.2.1...190.160.3.2  IKEv1
peer-190.160.3.2-tunnel-1:   local:  [190.160.2.1] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   remote: [190.160.3.2] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   child:  190.160.1.0/24[tcp/1024] === 190.160.4.0/24[tcp/1024] TUNNEL
Security Associations (1 up, 0 connecting):
peer-190.160.3.2-tunnel-1[3]: ESTABLISHED 29 minutes ago, 190.160.2.1[500][190.160.2.1]...190.160.3.2[500][190.160.3.2]
peer-190.160.3.2-tunnel-1[3]: IKEv1 SPIs: 7f3580eaa349d1b3_i* d15a87348b169da9_r, pre-shared key reauthentication in 15 minutes
peer-190.160.3.2-tunnel-1[3]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_2048
peer-190.160.3.2-tunnel-1{3}:  REKEYED, TUNNEL, reqid 3, expires in 22 seconds
peer-190.160.3.2-tunnel-1{3}:   190.160.1.0/24[tcp/1024] === 190.160.4.0/24[tcp/1024]
peer-190.160.3.2-tunnel-1{5}:  INSTALLED, TUNNEL, reqid 3, ESP SPIs: cf2b3689_i c5232e9b_o
peer-190.160.3.2-tunnel-1{5}:  AES_CBC_256/HMAC_MD5_96/MODP_2048, 0 bytes_i, 0 bytes_o, rekeying in 38 seconds
peer-190.160.3.2-tunnel-1{5}:   190.160.1.0/24[tcp/1024] === 190.160.4.0/24[tcp/1024]
EOF

our @charon_ipsec_statusall_esp_aes_gcm = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.13-1-amd64-vyatta, x86_64):
  uptime: 3 minutes, since Jun 21 18:37:45 2016
  malloc: sbrk 2543616, mmap 0, used 354272, free 2189344
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 5
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  172.27.246.101
  190.160.2.1
  190.160.1.2
Connections:
peer-190.160.3.2-tunnel-1:  190.160.2.1...190.160.3.2  IKEv2
peer-190.160.3.2-tunnel-1:   local:  [190.160.2.1] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   remote: [190.160.3.2] uses pre-shared key authentication
peer-190.160.3.2-tunnel-1:   child:  190.160.1.0/24 === 190.160.4.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
peer-190.160.3.2-tunnel-1[1]: ESTABLISHED 3 minutes ago, 190.160.2.1[500][190.160.2.1]...190.160.3.2[500][190.160.3.2]
peer-190.160.3.2-tunnel-1[1]: IKEv2 SPIs: 443174e688a88428_i* 9fa8e8a0357054ea_r, pre-shared key reauthentication in 9 hours
peer-190.160.3.2-tunnel-1[1]: IKE proposal: AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_1536
peer-190.160.3.2-tunnel-1{2}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: ce78b763_i ca005d50_o
peer-190.160.3.2-tunnel-1{2}:  AES_GCM_16_128, 0 bytes_i, 0 bytes_o, rekeying in 4 hours
peer-190.160.3.2-tunnel-1{2}:   190.160.1.0/24 === 190.160.4.0/24
EOF

our @charon_ipsec_statusall_hub_leftovers = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.15-1-amd64-vyatta, x86_64):
  uptime: 17 minutes, since Jul 26 23:24:43 2016
  malloc: sbrk 2408448, mmap 0, used 354592, free 2053856
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 2
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  10.250.0.213
  6.5.5.1
  21.0.0.1
Connections:
Security Associations (1 up, 0 connecting):
vpnprof-tunnel-tun0[1]: ESTABLISHED 16 minutes ago, 6.5.5.1[500][6.5.5.1]...6.5.5.10[500][6.5.5.10]
vpnprof-tunnel-tun0[1]: IKEv1 SPIs: ef1b5e185caae459_i 24da71f0aae48cb5_r*, rekeying disabled
vpnprof-tunnel-tun0[1]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
vpnprof-tunnel-tun0{1}:  REKEYED, TRANSPORT, reqid 1, expires in 17 minutes
vpnprof-tunnel-tun0{1}:   6.5.5.1/32[gre] === 6.5.5.10/32[gre]
vpnprof-tunnel-tun0{2}:  INSTALLED, TRANSPORT, reqid 1, ESP SPIs: c1ab3622_i c539b748_o
vpnprof-tunnel-tun0{2}:  AES_CBC_256/HMAC_SHA1_96/MODP_1536, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun0{2}:   6.5.5.1/32[gre] === 6.5.5.10/32[gre]
EOF

# Note that this splits the here document into an array of strings (per line)
# capture date: Mon May 11 10:52:43 GMT 2015
our @ip_xfrm_state_list_spi_unused = <<'EOF' =~ m/(^.*$)/mg;
src 192.168.100.6 dst 192.168.100.7
        proto esp spi 0xc02b62a8(3224068776) reqid 1(0x00000001) mode tunnel
        replay-window 32 seq 0x00000000 flag af-unspec (0x00100000)
        auth-trunc hmac(sha1) 0xce8b5ebbf372b564e558aea3950011f38aeae34c (160 bits) 96
        enc cbc(aes) 0xc7d053591043992998509cd843c87603f8c038f087812fda2b0abd9e301af21a (256 bits)
        lifetime config:
          limit: soft (INF)(bytes), hard (INF)(bytes)
          limit: soft (INF)(packets), hard (INF)(packets)
          expire add: soft 2883(sec), hard 3600(sec)
          expire use: soft 0(sec), hard 0(sec)
        lifetime current:
          0(bytes), 0(packets)
          add 2015-05-11 10:03:53 use -
        stats:
          replay-window 0 replay 0 failed 0
EOF

# Mon May 11 11:12:50 GMT 2015
our @ip_xfrm_state_list_spi = <<'EOF' =~ m/(^.*$)/mg;
src 192.168.100.6 dst 192.168.100.7
        proto esp spi 0xc02b62a8(3224068776) reqid 1(0x00000001) mode tunnel
        replay-window 32 seq 0x00000000 flag af-unspec (0x00100000)
        auth-trunc hmac(sha1) 0xce8b5ebbf372b564e558aea3950011f38aeae34c (160 bits) 96
        enc cbc(aes) 0xc7d053591043992998509cd843c87603f8c038f087812fda2b0abd9e301af21a (256 bits)
        lifetime config:
          limit: soft (INF)(bytes), hard (INF)(bytes)
          limit: soft (INF)(packets), hard (INF)(packets)
          expire add: soft 2883(sec), hard 3600(sec)
          expire use: soft 0(sec), hard 0(sec)
        lifetime current:
          252(bytes), 3(packets)
          add 2015-05-11 10:47:28 use 2015-05-11 10:55:26
        stats:
          replay-window 0 replay 0 failed 0
EOF

our @ipsec_conf_snippet = <<'EOF' =~ m/(^.*$)/mg;

conn %default
        keyexchange=ikev1

conn peer-192.168.100.6-tunnel-1
        left=192.168.100.7
        right=192.168.100.6
        leftsubnet=192.168.248.0/24
        rightsubnet=192.168.40.0/24
        ike=aes256-sha1-modp1536!
        ikelifetime=28800s
        esp=aes256-sha1!
        keylife=3600s
        rekeymargin=540s
        type=tunnel
        compress=no
        authby=secret
        auto=start
        keyingtries=%forever
        test=
#conn peer-192.168.100.6-tunnel-1

conn peer-11:1::2-tunnel-vti
        left=11:1::1
        right=11:1::2
        leftsubnet=192:168::1:1/128
        rightsubnet=192:168::1:2/128
        keyexchange=ikev1
        ike=aes256-sha1-modp1536,aes256-sha1-modp1024!
        ikelifetime=3600s
        esp=aes256-sha1-modp1536,aes256-sha1-modp1024!
        keylife=3600s
        rekeymargin=540s
        type=tunnel
        compress=no
        authby=secret
        auto=start
        keyingtries=%forever
#conn peer-11:1::2-tunnel-vti

EOF

our @vplsh_ipsec_sad = split(/\n/, <<EOF);

{
    "ipsec-sas": {
        "total-sas": 4
    },
    "sas": [{
            "spi": "d924e5c5",
            "cipher": "CBS(AES) 256",
            "digest": "hmac(sha1)",
            "bytes": 842,
            "packets": 0,
            "blocked": false
        },{
            "spi": "e2d71fc6",
            "cipher": "CBS(AES) 256",
            "digest": "hmac(sha1)",
            "bytes": 842,
            "packets": 0,
            "blocked": false
        },{
            "spi": "6937e8c0",
            "cipher": "CBS(AES) 256",
            "digest": "hmac(sha1)",
            "bytes": 0,
            "packets": 0,
            "blocked": false
        },{
            "spi": "b3ae30ce",
            "cipher": "CBS(AES) 256",
            "digest": "hmac(sha1)",
            "bytes": 0,
            "packets": 0,
            "blocked": false
        }
    ]
 }

EOF

our @vplsh_ipsec_sad_blocked = split(/\n/, <<EOF);
{
    "ipsec-sas": {
        "total-sas": 2
    },
    "sas": [{
            "spi": "9bf9eec5",
            "bytes": 4321,
            "packets": 0,
            "blocked": true
        },{
            "spi": "2fd3eacc",
            "bytes": 0,
            "packets": 1234,
            "blocked": false
        }
    ]
}
EOF

1;
