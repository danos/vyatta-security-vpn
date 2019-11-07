package TestData_Prof_OPMode;

use strict;
use warnings 'all';

use parent qw(Exporter);

our @EXPORT_OK = qw(@pluto_ipsec_statusall_up_up @charon_ipsec_statusall_up_up
                    @charon_ipsec_statusall_hub @charon_ipsec_statusall_peerid
                    @charon_ipsec_statusall_hub_two_spokes
                    @charon_ipsec_statusall_hub_two_profiles);

# Note that this splits the here document into an array of strings (per line)
our @pluto_ipsec_statusall_up_up = <<'EOF' =~ m/(^.*$)/mg;
000 Status of IKEv1 pluto daemon (strongSwan 4.5.2):
000 interface lo/lo ::1:500
000 interface lo/lo 127.0.0.1:500
000 interface eth0/eth0 10.250.0.203:500
000 interface dp0s4/dp0s4 192.168.101.12:500
000 interface dp0s5/dp0s5 192.168.104.12:500
000 interface dp0s8/dp0s8 192.168.103.12:500
000 interface dp0s9/dp0s9 192.168.102.12:500
000 interface tun999/tun999 100.100.100.1:500
000 %myid = '%any'
000 loaded plugins: test-vectors curl ldap aes des sha1 sha2 md5 random x509 pkcs1 pgp dnskey pem openssl gmp hmac xauth attr kernel-netlink resolve 
000 debug options: raw+crypt+parsing+emitting+control+lifecycle+kernel+dns+natt+oppo+controlmore
000 
000 "100.100.100.1-to-100.100.100.200": 192.168.103.12[192.168.103.12]:47/0...192.168.103.11[192.168.103.11]:47/0; erouted; eroute owner: #84
000 "100.100.100.1-to-100.100.100.200":   ike_life: 10800s; ipsec_life: 3600s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 3
000 "100.100.100.1-to-100.100.100.200":   policy: PSK+ENCRYPT+PFS+UP; prio: 32,32; interface: dp0s8; 
000 "100.100.100.1-to-100.100.100.200":   newest ISAKMP SA: #80; newest IPsec SA: #84; 
000 "100.100.100.1-to-100.100.100.200":   IKE proposal: AES_CBC_256/HMAC_SHA1/MODP_1024
000 "100.100.100.1-to-100.100.100.200":   ESP proposal: AES_CBC_256/HMAC_SHA1/<Phase1>
000 "vpnprof-tunnel-tun999": 192.168.103.12[192.168.103.12]:47/0...%any[%any]:47/0; unrouted; eroute owner: #0
000 "vpnprof-tunnel-tun999":   ike_life: 3600s; ipsec_life: 1800s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0
000 "vpnprof-tunnel-tun999":   dpd_action: restart; dpd_delay: 30s; dpd_timeout: 120s;
000 "vpnprof-tunnel-tun999":   policy: PSK+ENCRYPT+TUNNEL+PFS+DONTREKEY; prio: 32,32; interface: dp0s8; 
000 "vpnprof-tunnel-tun999":   newest ISAKMP SA: #0; newest IPsec SA: #0; 
000 
000 #84: "100.100.100.1-to-100.100.100.200" STATE_QUICK_I2 (sent QI2, IPsec SA established); EVENT_SA_REPLACE in 2020s; newest IPSEC; eroute owner
000 #84: "100.100.100.1-to-100.100.100.200" esp.c08bdbcf@192.168.103.11 (782 bytes, 35s ago) esp.cc56f45b@192.168.103.12 (882 bytes, 35s ago); tunnel
000 #80: "100.100.100.1-to-100.100.100.200" STATE_MAIN_I4 (ISAKMP SA established); EVENT_SA_REPLACE in 4431s; newest ISAKMP
000 
EOF

our @charon_ipsec_statusall_up_up = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.2.1, Linux 4.1.13-1-amd64-vyatta, x86_64):
  uptime: 2 minutes, since Nov 27 15:35:27 2015
  malloc: sbrk 2412544, mmap 0, used 348000, free 2064544
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 8
  loaded plugins: charon aes rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default stroke vici updown
Listening IP addresses:
  192.168.252.201
  10.10.2.2
  192.168.103.12
  200.0.0.11
Connections:
vpnprof-tunnel-tun999:  192.168.103.12...%any  IKEv1, dpddelay=15s
vpnprof-tunnel-tun999:   local:  [192.168.103.12] uses pre-shared key authentication
vpnprof-tunnel-tun999:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun999:   child:  dynamic[gre] === dynamic[gre] TUNNEL, dpdaction=hold
tun999-192.168.103.12-to-192.168.103.11:  192.168.103.12...192.168.103.11  IKEv1, dpddelay=15s
tun999-192.168.103.12-to-192.168.103.11:   local:  [192.168.103.12] uses pre-shared key authentication
tun999-192.168.103.12-to-192.168.103.11:   remote: [192.168.103.11] uses pre-shared key authentication
tun999-192.168.103.12-to-192.168.103.11:   child:  dynamic[gre] === dynamic[gre] TUNNEL, dpdaction=hold
Security Associations (1 up, 0 connecting):
tun999-192.168.103.12-to-192.168.103.11[1]: ESTABLISHED 112 seconds ago, 192.168.103.12[192.168.103.12]...192.168.103.11[192.168.103.11]
tun999-192.168.103.12-to-192.168.103.11[1]: IKEv1 SPIs: 114b90413efcd0d8_i* cf1b191c449eabb1_r, rekeying disabled
tun999-192.168.103.12-to-192.168.103.11[1]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
tun999-192.168.103.12-to-192.168.103.11{1}:  INSTALLED, TUNNEL, ESP SPIs: c5cf9e28_i c983bf65_o
tun999-192.168.103.12-to-192.168.103.11{1}:  AES_CBC_256/HMAC_SHA1_96, 0 bytes_i, 0 bytes_o, rekeying disabled
tun999-192.168.103.12-to-192.168.103.11{1}:   192.168.103.12/32[gre] === 192.168.103.11/32[gre]
EOF

our @charon_ipsec_statusall_peerid = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.11-1-amd64-vyatta, x86_64):
  uptime: 73 seconds, since May 27 01:44:29 2016
  malloc: sbrk 31531008, mmap 1052672, used 11630432, free 19900576
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 36920
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  10.37.109.71
  192.169.13.1
  3013::1
  192.168.13.1
  2013::1
  1.1.1.1
  11.11.11.11
  2111:0:130f::9c0:876a:ddd
  200.1.1.1
  101.1.1.1
  213.1.1.1
  2213::1
  215.1.1.1
  2215::1
  12.1.1.1
  2012::1
  3012::1
  212.1.1.1
  210.1.1.1
  2210::1
  211.1.1.1
  2211::1
  198.1.1.1
  99.1.1.1
Connections:
vpnprof-tunnel-tun0:  101.1.1.1...%any  IKEv1
vpnprof-tunnel-tun0:   local:  [101.1.1.1] uses pre-shared key authentication
vpnprof-tunnel-tun0:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun0:   child:  dynamic[gre] === 0.0.0.0/0[gre] TRANSPORT
tun0-101.1.1.1-to-102.1.1.1:  101.1.1.1...102.1.1.1  IKEv1
tun0-101.1.1.1-to-102.1.1.1:   local:  [101.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-102.1.1.1:   remote: [102.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-102.1.1.1:   child:  dynamic[gre] === 0.0.0.0/0[gre] TRANSPORT
tun0-101.1.1.1-to-108.1.1.1:  101.1.1.1...108.1.1.1  IKEv1
tun0-101.1.1.1-to-108.1.1.1:   local:  [101.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-108.1.1.1:   remote: [108.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-108.1.1.1:   child:  dynamic[gre] === 0.0.0.0/0[gre] TRANSPORT
tun0-101.1.1.1-to-109.1.1.1:  101.1.1.1...109.1.1.1  IKEv1
tun0-101.1.1.1-to-109.1.1.1:   local:  [101.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-109.1.1.1:   remote: [109.1.1.1] uses pre-shared key authentication
tun0-101.1.1.1-to-109.1.1.1:   child:  dynamic[gre] === 0.0.0.0/0[gre] TRANSPORT
Security Associations (98 up, 317 connecting):
   (unnamed)[1307]: IKEv1 SPIs: 16898d58574a1a2a_i 8827b69c35272d68_r*
   (unnamed)[1307]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
   (unnamed)[1307]: Tasks passive: ISAKMP_VENDOR MAIN_MODE ISAKMP_NATD
   (unnamed)[1297]: IKEv1 SPIs: 90c328bc80346776_i 0e84b125a967d6d6_r*
   (unnamed)[1297]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
   (unnamed)[1297]: Tasks passive: ISAKMP_VENDOR MAIN_MODE ISAKMP_NATD
   (unnamed)[1295]: IKEv1 SPIs: db82bf35d33c602c_i 147eef65a9dc11e6_r*
   (unnamed)[1295]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
   (unnamed)[1295]: Tasks passive: ISAKMP_VENDOR MAIN_MODE ISAKMP_NATD
   (unnamed)[1294]: IKEv1 SPIs: 78fff69d297fef54_i 98e406d4b638238f_r*
   (unnamed)[1294]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
   (unnamed)[1294]: Tasks passive: ISAKMP_VENDOR MAIN_MODE ISAKMP_NATD
   (unnamed)[1293]: IKEv1 SPIs: 4082c5c6eb47af38_i 81dce3f209dc34a6_r*
   (unnamed)[1293]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
   (unnamed)[1293]: Tasks passive: ISAKMP_VENDOR MAIN_MODE ISAKMP_NATD
tun0-101.1.1.1-to-109.1.1.1[225]: ESTABLISHED 67 seconds ago, 101.1.1.1[500][101.1.1.1]...109.1.1.1[500][109.1.1.1]
tun0-101.1.1.1-to-109.1.1.1[225]: IKEv1 SPIs: 5559828572a7ad0f_i* e1c0fc8f904ccf8e_r, pre-shared key reauthentication in 47 minutes
tun0-101.1.1.1-to-109.1.1.1[225]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
tun0-101.1.1.1-to-109.1.1.1{2}:  INSTALLED, TRANSPORT, reqid 2, ESP SPIs: c4e1a486_i c095e95e_o
tun0-101.1.1.1-to-109.1.1.1{2}:  AES_CBC_256/HMAC_SHA1_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 11 minutes
tun0-101.1.1.1-to-109.1.1.1{2}:   101.1.1.1/32[gre] === 109.1.1.1/32[gre]
tun0-101.1.1.1-to-108.1.1.1[224]: ESTABLISHED 67 seconds ago, 101.1.1.1[500][101.1.1.1]...108.1.1.1[500][108.1.1.1]
tun0-101.1.1.1-to-108.1.1.1[224]: IKEv1 SPIs: cfebfa84be74eeae_i* 54f6db0de4e3e758_r, pre-shared key reauthentication in 46 minutes
tun0-101.1.1.1-to-108.1.1.1[224]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
tun0-101.1.1.1-to-108.1.1.1{1}:  INSTALLED, TRANSPORT, reqid 1, ESP SPIs: cba18e99_i c5ae5657_o
tun0-101.1.1.1-to-108.1.1.1{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying in 12 minutes
tun0-101.1.1.1-to-108.1.1.1{1}:   101.1.1.1/32[gre] === 108.1.1.1/32[gre]
EOF

our @charon_ipsec_statusall_hub = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.8-1-amd64-vyatta, x86_64):
  uptime: 22 hours, since May 25 14:30:40 2016
  malloc: sbrk 2539520, mmap 0, used 435664, free 2103856
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 1
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  172.29.213.64
  4.4.4.64
  5.5.5.64
  10.5.5.64
Connections:
vpnprof-tunnel-tun0:  4.4.4.64...%any  IKEv1
vpnprof-tunnel-tun0:   local:  [4.4.4.64] uses pre-shared key authentication
vpnprof-tunnel-tun0:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun0:   child:  dynamic[gre] === 0.0.0.0/0[gre] TUNNEL
vpnprof-tunnel-tun1:  5.5.5.64...%any  IKEv1
vpnprof-tunnel-tun1:   local:  [5.5.5.64] uses pre-shared key authentication
vpnprof-tunnel-tun1:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun1:   child:  dynamic[gre] === 0.0.0.0/0[gre] TUNNEL
Security Associations (5 up, 0 connecting):
vpnprof-tunnel-tun1[14]: ESTABLISHED 2 minutes ago, 5.5.5.64[4500][5.5.5.64]...5.5.5.63[4500][10.10.4.63]
vpnprof-tunnel-tun1[14]: IKEv1 SPIs: d309c34a95e4e95a_i 3fa57cb37ea0bad8_r*, rekeying disabled
vpnprof-tunnel-tun1[14]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{1963}:  INSTALLED, TUNNEL, reqid 8, ESP in UDP SPIs: cd39a80b_i c515b62b_o
vpnprof-tunnel-tun1{1963}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{1963}:   5.5.5.64/32[gre] === 10.10.4.63/32[gre]
vpnprof-tunnel-tun1[13]: ESTABLISHED 2 minutes ago, 5.5.5.64[4500][5.5.5.64]...5.5.5.61[4500][10.10.4.61]
vpnprof-tunnel-tun1[13]: IKEv1 SPIs: b629d0bba4a2f110_i 4c178914d64a95a2_r*, rekeying disabled
vpnprof-tunnel-tun1[13]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{1962}:  INSTALLED, TUNNEL, reqid 7, ESP in UDP SPIs: ce0aca6b_i cd9505bc_o
vpnprof-tunnel-tun1{1962}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{1962}:   5.5.5.64/32[gre] === 10.10.4.61/32[gre]
vpnprof-tunnel-tun1[11]: ESTABLISHED 7 hours ago, 5.5.5.64[500][5.5.5.64]...5.5.5.62[500][5.5.5.62]
vpnprof-tunnel-tun1[11]: IKEv1 SPIs: c652fbd393081a64_i 2921956f8f1ebe98_r*, rekeying disabled
vpnprof-tunnel-tun1[11]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{1925}:  INSTALLED, TUNNEL, reqid 2, ESP SPIs: c8d91264_i cd309252_o
vpnprof-tunnel-tun1{1925}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{1925}:   5.5.5.64/32[gre] === 5.5.5.62/32[gre]
vpnprof-tunnel-tun0[5]: ESTABLISHED 22 hours ago, 4.4.4.64[500][4.4.4.64]...4.4.4.73[500][4.4.4.73]
vpnprof-tunnel-tun0[5]: IKEv1 SPIs: 60929869df5e0ab2_i 2d41c6d201dc56bb_r*, rekeying disabled
vpnprof-tunnel-tun0[5]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun0{1965}:  REKEYED, TUNNEL, reqid 5, expires in 26 hours
vpnprof-tunnel-tun0{1965}:   4.4.4.64/32[gre] === 4.4.4.73/32[gre]
vpnprof-tunnel-tun0{1967}:  INSTALLED, TUNNEL, reqid 5, ESP SPIs: cf736dcc_i 95814024_o
vpnprof-tunnel-tun0{1967}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun0{1967}:   4.4.4.64/32[gre] === 4.4.4.73/32[gre]
vpnprof-tunnel-tun1[4]: ESTABLISHED 22 hours ago, 5.5.5.64[4500][5.5.5.64]...5.5.5.74[4500][10.10.4.74]
vpnprof-tunnel-tun1[4]: IKEv1 SPIs: 1d20d9f9e9511e9d_i 4392fe64352bde90_r*, rekeying disabled
vpnprof-tunnel-tun1[4]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{1966}:  INSTALLED, TUNNEL, reqid 4, ESP in UDP SPIs: c2c14c37_i dcbfdbfc_o
vpnprof-tunnel-tun1{1966}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{1966}:   5.5.5.64/32[gre] === 10.10.4.74/32[gre]
EOF

our @charon_ipsec_statusall_hub_two_spokes = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.11-1-amd64-vyatta, x86_64):
  uptime: 4 minutes, since May 31 19:22:26 2016
  malloc: sbrk 2543616, mmap 0, used 375712, free 2167904
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 0
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  30.0.0.1
  20.0.0.1
  192.1.0.1
  192.3.0.1
  10.25.148.193
  10.1.100.101
  200.0.0.99
Connections:
vpnprof-tunnel-tun0:  20.0.0.1...%any  IKEv1
vpnprof-tunnel-tun0:   local:  [20.0.0.1] uses pre-shared key authentication
vpnprof-tunnel-tun0:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun0:   child:  dynamic[gre] === 0.0.0.0/0[gre] TUNNEL
Security Associations (2 up, 0 connecting):
vpnprof-tunnel-tun0[2]: ESTABLISHED 2 minutes ago, 20.0.0.1[500][20.0.0.1]...30.0.0.2[500][30.0.0.2]
vpnprof-tunnel-tun0[2]: IKEv1 SPIs: 9f1b66574b6a0a8e_i 5e8371c6e00cda42_r*, rekeying disabled
vpnprof-tunnel-tun0[2]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
vpnprof-tunnel-tun0{2}:  INSTALLED, TUNNEL, reqid 2, ESP SPIs: c5b25910_i cc9f8a7f_o
vpnprof-tunnel-tun0{2}:  AES_CBC_256/HMAC_SHA1_96/MODP_1536, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun0{2}:   20.0.0.1/32[gre] === 30.0.0.2/32[gre]
vpnprof-tunnel-tun0[1]: ESTABLISHED 3 minutes ago, 20.0.0.1[500][20.0.0.1]...20.0.0.2[500][20.0.0.2]
vpnprof-tunnel-tun0[1]: IKEv1 SPIs: d9bbc6f95669686f_i 6cfe83bcf91650e9_r*, rekeying disabled
vpnprof-tunnel-tun0[1]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1536
vpnprof-tunnel-tun0{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c7672d1b_i cb56eea3_o
vpnprof-tunnel-tun0{1}:  AES_CBC_256/HMAC_SHA1_96/MODP_1536, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun0{1}:   20.0.0.1/32[gre] === 20.0.0.2/32[gre]
EOF

our @charon_ipsec_statusall_hub_two_profiles = <<'EOF' =~ m/(^.*$)/mg;
Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.12-1-amd64-vyatta, x86_64):
  uptime: 23 hours, since Jun 07 09:59:04 2016
  malloc: sbrk 2539520, mmap 0, used 401792, free 2137728
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 0
  loaded plugins: charon rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke vici updown
Listening IP addresses:
  172.29.213.64
  4.4.4.64
  5.5.5.64
  10.5.5.64
Connections:
vpnprof-tunnel-tun0:  4.4.4.64...%any  IKEv1
vpnprof-tunnel-tun0:   local:  [4.4.4.64] uses pre-shared key authentication
vpnprof-tunnel-tun0:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun0:   child:  dynamic[gre] === 0.0.0.0/0[gre] TUNNEL
vpnprof-tunnel-tun1:  5.5.5.64...%any  IKEv1
vpnprof-tunnel-tun1:   local:  [5.5.5.64] uses pre-shared key authentication
vpnprof-tunnel-tun1:   remote: uses pre-shared key authentication
vpnprof-tunnel-tun1:   child:  dynamic[gre] === 0.0.0.0/0[gre] TUNNEL
Security Associations (3 up, 0 connecting):
vpnprof-tunnel-tun1[9]: ESTABLISHED 3 hours ago, 5.5.5.64[4500][5.5.5.64]...5.5.5.61[4500][10.10.4.61]
vpnprof-tunnel-tun1[9]: IKEv1 SPIs: 5680c62e944e1508_i af55f4e875cb4636_r*, rekeying disabled
vpnprof-tunnel-tun1[9]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{86}:  REKEYED, TUNNEL, reqid 3, expires in 23 hours
vpnprof-tunnel-tun1{86}:   5.5.5.64/32[gre] === 10.10.4.61/32[gre]
vpnprof-tunnel-tun1{89}:  INSTALLED, TUNNEL, reqid 3, ESP in UDP SPIs: c7d02e72_i ceac9f5c_o
vpnprof-tunnel-tun1{89}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{89}:   5.5.5.64/32[gre] === 10.10.4.61/32[gre]
vpnprof-tunnel-tun1[8]: ESTABLISHED 7 hours ago, 5.5.5.64[4500][5.5.5.64]...5.5.5.63[4500][10.10.4.63]
vpnprof-tunnel-tun1[8]: IKEv1 SPIs: 983aada8a463ac29_i 34102c8bb423f5ed_r*, rekeying disabled
vpnprof-tunnel-tun1[8]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{88}:  INSTALLED, TUNNEL, reqid 1, ESP in UDP SPIs: c60be2ab_i c6a144ed_o
vpnprof-tunnel-tun1{88}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{88}:   5.5.5.64/32[gre] === 10.10.4.63/32[gre]
vpnprof-tunnel-tun1[7]: ESTABLISHED 7 hours ago, 5.5.5.64[500][5.5.5.64]...5.5.5.62[500][5.5.5.62]
vpnprof-tunnel-tun1[7]: IKEv1 SPIs: d7b7d64e414fe842_i e276375b7f712160_r*, rekeying disabled
vpnprof-tunnel-tun1[7]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
vpnprof-tunnel-tun1{87}:  INSTALLED, TUNNEL, reqid 2, ESP SPIs: caed92a5_i ceb2eadd_o
vpnprof-tunnel-tun1{87}:  3DES_CBC/HMAC_MD5_96/MODP_1024, 0 bytes_i, 0 bytes_o, rekeying disabled
vpnprof-tunnel-tun1{87}:   5.5.5.64/32[gre] === 5.5.5.62/32[gre]
EOF

1;
