#!/usr/bin/python3
# Copyright (c) 2017-2020 AT&T Intellectual Property.
# All Rights Reserved.

# SPDX-License-Identifier: GPL-2.0-only

import os
import socket
import sys
import time
import vici
import dbus

from collections import OrderedDict

IPSEC_RA_VPN_SERVER_NAMEPREFIX = 'ipsec-remote-access-server'

DH2MODP = {
    2:'modp1024',
    5:'modp1536',
    14:'modp2048',
    15:'modp3072',
    16:'modp4096',
    17:'modp6144',
    18:'modp8192',
    19:'ecp256',
    20:'ecp384'
}

IKE_REKEY_MARGIN = 0.1 # relative
ESP_REKEY_MARGIN = 0.1 # relative

DBUS_INTERFACE = 'net.vyatta.eng.security.vpn.ipsec'
DBUS_OBJECT    = '/net/vyatta/eng/security/vpn/ipsec'
DBUS_CONN_RETRIES = 3

def err(msg):
    print(msg, file=sys.stderr)

IKE_SA_DAEMON = None

def setup_dbus():
    global IKE_SA_DAEMON
    if IKE_SA_DAEMON:
        return IKE_SA_DAEMON

    bus = dbus.SystemBus()

    retries = DBUS_CONN_RETRIES
    while IKE_SA_DAEMON == None and retries > 0:
        try:
            IKE_SA_DAEMON = bus.get_object(DBUS_INTERFACE, DBUS_OBJECT)
        except dbus.DBusException as e:
            time.sleep(0.5)
            retries -= 1

    if IKE_SA_DAEMON:
        return IKE_SA_DAEMON
    else:
        raise ConnectionRefusedError

def setup_vici():
    s = socket.socket(socket.AF_UNIX)
    retry = True
    while True:
        try:
            s.connect("/var/run/charon.vici")
            break
        except (ConnectionRefusedError, FileNotFoundError) as e:
            if retry:
                rc = os.system('/opt/vyatta/sbin/vyatta-restart-vpn restart')
                if rc >> 8 == 1:
                    return None
                retry = False
                time.sleep(2)
            else:
                raise(e)

    return vici.Session(s)

def proposal2str(enc, h, dht):
    """create a proposal from vyatta config values"""
    if h != None and h != 'null':
        enc += '-{}'.format(h)
    if len(dht) == 0:
        return [enc.encode()]
    else:
        return ['{}-{}'.format(enc, DH2MODP[t]).encode() for t in dht]

def dpd_action2vici(dpd_action):
    if dpd_action == 'hold':
        return 'trap'
    if dpd_action in ('clear', 'restart'):
        return dpd_action
    return None

def get_cert_or_key(cert_type, cert_flag, cert_cfg_data):
    cert = OrderedDict()
    cert['type'] = cert_type
    if cert_flag:
       cert['flag'] = cert_flag
    if cert_cfg_data[0] == '/':
       try:
           with open(cert_cfg_data, mode='r', encoding='utf-8') as f:
               cert['data'] = f.read()
       except EnvironmentError as e:
           err("can't open {} \"{}\": {}".format(cert_type, cert_cfg_data, e))
           sys.exit(1)
    else:
       cert['data'] = cert_cfg_data.replace('\\n', '\n')

    return cert



class IKEGroup:
    """Represent a single IKE Group in vyatta configuration.
    Args:
        cfg (dict): a dictionary holding the "ipsec ike-group <name>"
        configuration tree.
    """
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg['tagnode']
        self.props = None
        self.dhg = None
        self.dpd_cfg = self.cfg.get('dead-peer-detection')

        # CLI lifetime means Hard IKE SA lifetime
        # CLI/hard lifetime = rekey_time + over_time
        lifetime = self.cfg.get('lifetime')
        self.rekey_time = int(lifetime * (1 - IKE_REKEY_MARGIN))
        self.over_time  = int(lifetime * IKE_REKEY_MARGIN)

    def proposals(self):
        """create and returns a list of binary encoded proposals"""
        if self.props != None:
            return self.props
        self.props = []
        self.dhg = []
        for prop in self.cfg['proposal']:
            enc, h, dh = (prop.get(k) for k in ('encryption', 'hash', 'dh-group'))
            dht = (dh,) if dh != None else (5, 2)
            self.props += proposal2str(enc, h, dht)
            self.dhg += filter(lambda d: d not in self.dhg, dht)
        return self.props

    def dh_groups(self):
        """returns list dh_groups used in this ike group"""
        if self.dhg != None:
            return self.dhg
        self.proposals()
        return self.dhg

    def dpd_get(self, name):
        return self.dpd_cfg.get(name) if self.dpd_cfg != None else None

class ESPGroup:
    def __init__(self, cfg):
        self.cfg = cfg
        self.name = cfg['tagnode']

    def get(self, name):
        return self.cfg.get(name)

    def get_dh(self, ike_dh):
        pfs = self.cfg['pfs']
        if pfs == 'enable':
            return ike_dh
        elif pfs is None or pfs == 'disable':
            return ()
        else:
            return (int(pfs[len('dh-group'):]),)

    def proposals(self, ike_dh):
        dh = self.get_dh(ike_dh)
        esp_proposals = []
        for prop in self.cfg['proposal']:
            enc, h = (prop.get(k) for k in ('encryption', 'hash'))
            esp_proposals += proposal2str(enc, h, dh)
        return esp_proposals

class Tunnel:
    def __init__(self, cfg, ikeg, espg, vrf_interfaces=None):
        self.cfg = cfg
        self.ike_group = ikeg
        self.esp_group = espg
        self.id = cfg['tunnel-id']
        self.data = None
        self.vrf_interfaces = vrf_interfaces

    def get(self, name):
        return self.cfg.get(name)

    def ts(self, net, port):
        proto = self.get('protocol')
        if port is None and proto is None:
            return [net.encode()]
        if port is None and proto is not None:
            return ['{}[{}]'.format(net, proto).encode()]
        if port is not None and proto is None:
            return ['{}[0/{}]'.format(net, port).encode()]
        if port != None and proto != None:
            return ['{}[{}/{}]'.format(net, proto, port).encode()]
        return None

    def connection_name(self, prefix):
        return "{}-tunnel-{}".format(prefix, self.id)

    def local(self):
        x = self.get('local')
        if x == None:
            return None
        else:
            return self.ts(x.get('network'), x.get('port'))

    def remote(self):
        x = self.get('remote')
        if x == None:
            return None
        else:
            return self.ts(x.get('network'), x.get('port'))

    def section(self, prefix):
        if self.data is None:
            proposals = self.esp_group.proposals(self.ike_group.dh_groups())
            self.data = OrderedDict([('esp_proposals', proposals)])
            remote_ts = self.remote()
            local_ts = self.local()
            if remote_ts != None:
                self.data['remote_ts'] = remote_ts
            if local_ts != None:
                self.data['local_ts'] = local_ts
            lifetime = self.esp_group.get('lifetime')
            if lifetime != None:
                rekey_time = int(lifetime * (1 - ESP_REKEY_MARGIN))
                self.data['life_time'] = str(lifetime).encode()
                self.data['rekey_time'] = str(rekey_time).encode()
            dpd_action = self.ike_group.dpd_get('action')
            if dpd_action != None:
                self.data['dpd_action'] = dpd_action2vici(dpd_action)
            self.data['updown'] = '/usr/lib/ipsec/vyatta-dataplane-s2s-updown'.encode()
            mode = self.esp_group.get('mode')
            self.data['mode'] = mode.encode()
            if self.get('vyatta-security-vpn-ipsec-vfp-v1:uses'):
                vfp_intf = self.get('vyatta-security-vpn-ipsec-vfp-v1:uses')
            elif self.get('uses'):
                vfp_intf = self.get('uses')
            else:
                vfp_intf = None
            if vfp_intf:
                self.data['interface'] = vfp_intf.encode()
                if self.vrf_interfaces:
                    routing_instance = self.vrf_interfaces.get(vfp_intf)
                else:
                    routing_instance = None
                if routing_instance:
                    domain_value = 'vrf' + routing_instance
                    self.data['domain'] = domain_value.encode()

        return [(self.connection_name(prefix), self.data)]

class Authentication:
    def __init__(self, cfg):
        self.cfg = cfg
        self.psk = None
        self.username = None
        self.password = None
        self.cert = None
        self.certkey = None
        self.local_id = None

        self.reauth_time = cfg.get('reauth-time')

        if cfg['mode'] == 'psk+eap-gtc':
            self.mode = 'psk+eap-gtc'
            self.psk = cfg['pre-shared-secret']
            self.username = cfg['username']
            self.password = cfg['password']
        elif cfg['mode'] == 'x509':
            self.mode = 'x509'
            self.cert = cfg['x509']['cert-file']
            self.certkey = cfg['x509']['key']['file']
            self.revocation = cfg['x509'].get('revocation-policy')
        else:
            err("mode {} not supported".format(cfg['mode']))

        if cfg.get('id'):
            self.local_id = '{}:{}'.format(cfg['id']['type'], cfg['id']['value'])

    def get(self, name):
        return self.cfg.get(name)

    def section(self):
        if self.mode == 'psk+eap-gtc':
            local_1 = OrderedDict([('auth', 'psk'.encode())])
            if self.local_id:
               local_1['id'] = self.local_id.encode()

            local_2 = OrderedDict([('auth', 'eap-gtc'.encode()), ('id', self.username.encode())])

            remote = OrderedDict([('auth', 'psk'.encode())])

            return [('local-1', local_1), ('local-2', local_2), ('remote', remote)]
        if self.mode == 'x509':
            local_1 = OrderedDict([('auth', 'pubkey'.encode())])
            local_1['cert-1'] = OrderedDict([('file', self.cert.encode())])
            if self.local_id:
               local_1['id'] = self.local_id.encode()

            remote = OrderedDict([('auth', 'pubkey'.encode())])
            if self.revocation:
               remote['revocation'] = self.revocation.encode()

            return [('local-1', local_1), ('remote-1', remote)]
        return None

    def shared_secrets(self, peers):
        authid = peers
        s = []

        if self.psk:
            s += [OrderedDict([('type', 'IKE'),
                             ('data', self.psk.encode()),
                             ('id', item['serveraddr'].encode())]) for item in authid]

        if self.password and self.username:
            s += [OrderedDict([
                             ('type', 'EAP'), ('data', self.password.encode()),
                             ('id', self.username.encode())])]
        return s

    def key(self):
        if self.certkey is None:
            return []

        return [get_cert_or_key('any', None, self.certkey)]


class ClientProfile:
    def __init__(self, cfg, ike_groups, esp_groups, vrf_interfaces):
        self.cfg = cfg
        self.name = cfg['profile-name']
        self.peers = cfg['server']
        self.ike = ike_groups[cfg['ike-group']]
        self.esp = esp_groups[cfg['esp-group']]
        if 'tunnel' in cfg:
            self.tunnels = list([Tunnel(t, self.ike, self.esp, vrf_interfaces) for t in cfg['tunnel']])
        else:
            self.tunnels = []
        self.auth = Authentication(cfg['authentication'])
        self.local_addr = cfg.get('local-address')
        self.install_virtual_ip_on = cfg.get('install-vip-on')

    def conn_name(self, peer, oif):
        NAMEPREFIX = "ipsec_ra_client"
        if oif:
            return '{}-{!s}-{!s}-{!s}'.format(NAMEPREFIX, self.name, oif, peer)
        else:
            return '{}-{!s}-{!s}'.format(NAMEPREFIX, self.name, peer)

    def peer_section(self, peer):
        od = OrderedDict()
        if peer.get('source-interface'):
            for oif in peer['source-interface']:
                od.update(self.peer_dict(peer, oif['ifname']))
        else:
            od.update(self.peer_dict(peer, None))

        return od

    def peer_dict(self, peer, oif):
        od = OrderedDict([('version', b'2')])
        od['mobike'] = 'no'
        od['rekey_time'] = str(self.ike.rekey_time).encode()
        od['over_time'] = str(self.ike.over_time).encode()
        if self.local_addr != None:
            od['local_addrs'] = [self.local_addr.encode()]
        if self.install_virtual_ip_on != None:
            od['install_virtual_ip_on'] = self.install_virtual_ip_on.encode()
        if oif:
            od['source_interface'] = oif.encode()
        od['remote_addrs'] = [peer['serveraddr'].encode()]
        od['vips'] = ['0.0.0.0'.encode(), '::'.encode()]
        od['proposals'] = self.ike.proposals()
        od.update(self.auth.section())
        dpd_delay = self.ike.dpd_get('interval')
        if dpd_delay != None:
            od['dpd_delay'] = dpd_delay
        tun_section = [t.section(self.conn_name(peer['serveraddr'], oif)) for t in self.tunnels]
        od.update([('children',
                    OrderedDict([item for sublist in tun_section for item in sublist]))])
        return OrderedDict([(self.conn_name(peer['serveraddr'], oif), od)])

    def section(self):
        od = OrderedDict()
        for peer in self.peers:
            od.update(self.peer_section(peer))
        return od

    def shared_secrets(self):
        return self.auth.shared_secrets(self.peers)

    def key(self):
        return self.auth.key()

class IPsecRAVPNServerProfile():
    def __init__(self, cfg, ike_groups, esp_groups):
        self.cfg = cfg
        self.name = cfg['profile-name']
        self.ike = ike_groups[cfg['ike-group']]
        self.esp = esp_groups[cfg['esp-group']]

        self.tunnels = list([Tunnel(t, self.ike, self.esp) for t in cfg['tunnel']])

        poolnames = []
        for pool in cfg['pools']:
            poolnames.append(pool['poolname'])

        self.pools =  ",".join(poolnames)

        self.auth = Authentication(cfg['authentication'])
        self.local_addr = cfg.get('local-address')


    def conn_name(self):
        return '{}-{!s}'.format(IPSEC_RA_VPN_SERVER_NAMEPREFIX, self.name)


    def key(self):
        return self.auth.key()

    def section(self):
        profile = OrderedDict()

        profile['version'] = b'2'
        profile['mobike'] = b'no'

        if self.cfg.get('force-udp-encap'):
            profile['encap'] = b'yes'

        profile['rekey_time'] = str(self.ike.rekey_time).encode()
        if self.auth.reauth_time:
            profile['reauth_time'] = str(self.auth.reauth_time).encode()
        profile['over_time'] = str(self.ike.over_time).encode()

        if self.local_addr != None:
            profile['local_addrs'] = [self.local_addr.encode()]

        profile['proposals'] = self.ike.proposals()

        profile.update(self.auth.section())
        profile['pools'] = [self.pools.encode()]

        dpd_delay = self.ike.dpd_get('interval')

        if dpd_delay != None:
            profile['dpd_delay'] = dpd_delay

        tun_section = [t.section(self.conn_name()) for t in self.tunnels]
        profile.update([('children',
                    OrderedDict([item for sublist in tun_section for item in sublist]))])

        return OrderedDict([(self.conn_name(), profile)])

class IPsecRAVPNServerPool():
    def __init__(self, cfg):
        self.cfg = cfg

    def pool_name(self):
        return self.cfg['pool-ref']

    def section(self):
        if not self.cfg.get('subnet'):
            return OrderedDict()

        pool = OrderedDict([('addrs', self.cfg['subnet'])])
        return OrderedDict([(self.pool_name(), pool)])

class IPsecRAVPNServer():
    def __init__(self, vs, cfg, ike_groups, esp_groups):
        self.vs = vs
        self.cfg = cfg
        self.ike_groups = ike_groups
        self.esp_groups = esp_groups
        self.keys = []
        self.pools = OrderedDict()
        self.profiles = OrderedDict()

        if cfg is None:
            return

        for p in cfg.get('pool'):
            self.pools.update(IPsecRAVPNServerPool(p).section())

        for p in cfg.get('profile'):
            profile = IPsecRAVPNServerProfile(p, ike_groups, esp_groups)
            self.profiles.update(profile.section())
            key = profile.key()
            if key:
                self.keys.extend(key)

    def sync(self):
        vs = self.vs

        # Delete stale connections / pools
        existing_conns = vs.get_conns().get('conns')
        stale_conns = list(filter(lambda x: x.startswith(IPSEC_RA_VPN_SERVER_NAMEPREFIX.encode()) and x not in self.profiles.keys(), existing_conns))
        for c in stale_conns:

            # Don't wait for IKE SA delete responses
            stream = vs.terminate(OrderedDict(ike=c, force=b'yes'))

            last_ike_log_msg = None
            try:
                for l in stream:
                    if l['group'] == b'IKE':
                        last_ike_log_msg = l['msg'].decode('ascii')
            except vici.exception.CommandException as e:
                pass

            vs.unload_conn(OrderedDict(name=c))

        existing_pools = vs.get_pools(OrderedDict()).keys()
        stale_pools = list(filter(lambda x: x not in self.pools.keys(), existing_pools))

        # There is a race between terminating peers and releasing IP leases from
        # IP pools. unload_pool() would fail if a lease is still online.
        # For that reason wait a brief moment if there have been stale connections
        # prior deleting stale pools.
        if stale_conns and stale_pools:
            time.sleep(0.1)

        for p in stale_pools:
            vs.unload_pool(OrderedDict(name=p))


        # Load or update existing configurations
        # Load order: keys, pools, profiles/connections
        for k in self.keys:
            vs.load_key(k)

        vs.load_pool(self.pools)

        vs.load_conn(self.profiles)


