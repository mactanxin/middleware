#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions # are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import errno
import logging
import ipaddress

from datastore.config import ConfigNode
from task import Task, Provider, VerifyException, TaskException, TaskDescription
from lib.system import system, SubprocessException
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, accepts, returns, description


logger = logging.getLogger(__name__)


@description('Provides OpenVPN service configuration')
class OpenVpnProvider(Provider):
    @returns(h.ref('ServiceOpenvpn'))
    def get_config(self):
        return ConfigNode('service.openvpn', self.configstore).__getstate__()

    @returns(h.ref('ServiceOpenvpn'))
    def get_readable_config(self):
        vpn_config = ConfigNode('service.openvpn', self.configstore).__getstate__()

        if vpn_config['ca']:
            vpn_config['ca'] = self.dispatcher.call_sync(
                'crypto.certificate.query', [('id', '=', vpn_config['ca'])], {'single': True, 'select': 'name'}
            )
        if vpn_config['cert']:
            vpn_config['cert'] = self.dispatcher.call_sync(
                'crypto.certificate.query', [('id', '=', vpn_config['cert'])], {'single': True, 'select': 'name'}
            )
        if vpn_config['key']:
            vpn_config['key'] = self.dispatcher.call_sync(
                'crypto.certificate.query', [('id', '=', vpn_config['key'])], {'single': True, 'select': 'name'}
            )

        return vpn_config

@description('Provides corresponding OpenVPN client configuration')
class OpenVPNClientConfigProvider(Provider):
    """This provider is responsible for returning corresponding client configuration.
       provide_tls_auth_key retruns generated static key which needs to by copied to
       the client OpenVPN directory with 'ta.key' file name.
    """
    @returns(str)
    def get_config(self):
        try:
            with open('/usr/local/etc/openvpn/openvpn_client', 'r') as f:
                return f.read()

        except FileNotFoundError:
            raise RpcException(errno.ENOENT, 'Client config file not available. '
                               'Please configure OpenVPN server first.')

    @returns(str)
    def get_tls_auth_key(self):
        node = ConfigNode('service.openvpn', self.configstore).__getstate__()
        return node['tls_auth']


@description('Creates OpenVPN config file')
@accepts(h.ref('ServiceOpenvpn'))
class OpenVpnConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring OpenVPN service'

    def describe(self, openvpn):
        return TaskDescription('Configuring OpenVPN service')

    def verify(self, openvpn_updated):
        node = ConfigNode('service.openvpn', self.configstore).__getstate__()
        node.update(openvpn_updated)

        if node['dev'] not in ['tap', 'tun']:
            raise VerifyException(errno.EINVAL, '{0} Bad interface name. Allowed values tap/tun.'.format(node['dev']))

        if node['mode'] == 'pki' and (not node['ca'] or not node['cert']):
            raise VerifyException(errno.EINVAL,
                                  'For pki VPN mode ca and certyficate values are required')

        if node['mode'] == 'psk':
            try:
                ipaddress.ip_address(node['psk_server_ip'])
                ipaddress.ip_address(node['psk_remote_ip'])
            except ValueError as e:
                raise VerifyException(errno.EINVAL, str(e))

        if node['mode'] == 'pki':
            if (node['keepalive_ping_interval'] * 2) >= node['keepalive_peer_down']:
                raise VerifyException(errno.EINVAL, 'The second parameter to keepalive must be'
                                      'at least twice the value of the first parameter.'
                                      'Recommended setting is keepalive 10 60.')

            try:
                ipaddress.IPv4Network(node['server_ip'] + '/' + node['server_netmask'])
            except ValueError as e:
                raise VerifyException(errno.EINVAL, str(e))


            for route in node.get('push_routes', []):
                route = route.split()
                if len(route) < 2:
                    raise VerifyException(errno.EINVAL, 'Wrong syntax for additional route.')
                try:
                    ipaddress.IPv4Network(route[0] + '/' + route[1])
                except ValueError as e:
                    raise VerifyException(errno.EINVAL, str(e))

        return ['system']

    def run(self, openvpn_updated):
        node = ConfigNode('service.openvpn', self.configstore).__getstate__()
        node.update(openvpn_updated)

        if node['mode'] == 'pki':

            ca_cert = self.dispatcher.call_sync(
                'crypto.certificate.query',
                [('id', '=', node['ca'])],
                {'single': True, 'select': 'id'}
            )

            if not ca_cert:
                    raise TaskException(errno.EINVAL, 'Provided CA certificate does not exist in config database.')

            else:
                openvpn_updated['ca'] = ca_cert

            cert = self.dispatcher.call_sync(
                'crypto.certificate.query', [('id', '=', node['cert'])], {'single': True, 'select': 'id'}
            )

            if not cert:
                raise TaskException(errno.EINVAL, 'Provided certificate does not exist in config database.')
            else:
                openvpn_updated['key'] = cert
                openvpn_updated['cert'] = cert

            openvpn_user = self.datastore.exists('users', ('username', '=', node['user']))
            if not openvpn_user:
                raise TaskException(errno.EINVAL, 'Provided user does not exist.')

            openvpn_group = self.datastore.exists('groups', ('name', '=', node['group']))
            if not openvpn_group:
                raise TaskException(errno.EINVAL, 'Provided user does not exist.')


        try:
            node = ConfigNode('service.openvpn', self.configstore)
            node.update(openvpn_updated)

            self.dispatcher.call_sync('etcd.generation.generate_group', 'openvpn')
            self.dispatcher.dispatch_event('service.openvpn.changed', {
                'operation': 'update',
                'ids': None,
            })

        except RpcException as e:
            raise TaskException(errno.ENXIO,
                                'Cannot reconfigure OpenVPN: {0}'.format(str(e)))

        return 'RESTART'


@accepts(str, h.any_of(int, None))
@description('Generates Diffie-Hellman parameters and tls-auth key file')
class OpenVPNGenerateKeys(Task):
    """ To get it working properly you need to set appropriate timeout on dipatcher client.
        Generation of 2048 bit dh parameters can take a long time.
    """
    @classmethod
    def early_describe(cls):
        return 'Generating OpenVPN cryptographic parameters'

    def describe(self, key_type, key_length):
        return TaskDescription('Generating {key_type} OpenVPN cryptographic values', key_type=key_type)

    def verify(self, key_type, key_length):
        if key_type not in ['dh-parameters', 'tls-auth-key']:
            raise VerifyException(errno.EINVAL, 'Type dh-parameters or tls-auth-key')

        if key_length and key_type == 'dh-parameters':
            if key_length not in [1024, 2048]:
                raise VerifyException(errno.EINVAL,
                                      'You have to chose between 1024 and 2048 bits.')

        if not key_length and key_type == 'dh-parameters':
                raise VerifyException(errno.EINVAL, 'You have to chose between 1024 and 2048 bits.')

        return['system']

    def run(self, key_type, key_length):
        try:
            if key_type == 'dh-parameters':
                dhparams = system('/usr/bin/openssl', 'dhparam', str(key_length))[0]

                self.configstore.set('service.openvpn.dh', dhparams)
                self.dispatcher.call_sync('etcd.generation.generate_group', 'openvpn')
                self.dispatcher.dispatch_event('service.openvpn.changed', {
                    'operation': 'update',
                    'ids': None,
                })

            else:
                tls_auth_key = system('/usr/local/sbin/openvpn', '--genkey', '--secret', '/dev/stdout')[0]

                self.configstore.set('service.openvpn.tls_auth', tls_auth_key)
                self.dispatcher.call_sync('etcd.generation.generate_group', 'openvpn')
                self.dispatcher.dispatch_event('service.openvpn.changed', {
                    'operation': 'update',
                    'ids': None,
                })

        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure OpenVPN: {0}'.format(str(e)))

        except SubprocessException as e:
            raise TaskException(errno.ENOENT, 'Cannont create requested key - check your system setup {0}'.format(e))



def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    if not dispatcher.configstore.get('service.openvpn.dh'):
        try:
            dhparams = system('/usr/bin/openssl', 'dhparam', '1024')[0]

        except SubprocessException as e:
            logger.warning('Cannot create initial dh parameters. Check openssl setup: {0}'.format(e))

        else:
            dispatcher.configstore.set('service.openvpn.dh', dhparams)

    if not dispatcher.configstore.get('service.openvpn.tls_auth'):
        try:
            tls_auth_key = system('/usr/local/sbin/openvpn', '--genkey', '--secret', '/dev/stdout')[0]

        except SubprocessException as e:
            logger.warning('Cannot create initial dh parameters. Check openvpn setup: {0}'.format(e))

        else:
            dispatcher.configstore.set('service.openvpn.tls_auth', tls_auth_key)

    plugin.register_schema_definition('ServiceOpenvpn', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceOpenvpn']},
            'enable': {'type': 'boolean'},
            'mode': {'type': 'string', 'enum': ['pki', 'psk']},
            'dev': {'type': 'string'},
            'persist_key': {'type': 'boolean'},
            'persist_tun': {'type': 'boolean'},
            'ca': {'type': 'string'},
            'cert': {'type': 'string'},
            'key': {'type': 'string'},
            'dh': {'type': 'string'},
            'tls_auth': {'type': ['string', 'null']},
            'cipher': {'type': 'string', 'enum': ['BF-CBC', 'AES-128-CBC', 'DES-EDE3-CBC']},
            'psk_server_ip': {'type': 'string'},
            'psk_remote_ip': {'type': 'string'},
            'server_ip': {'type': 'string'},
            'server_netmask': {'type': 'string'},
            'max_clients': {'type': 'integer'},
            'push_routes': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            },
            'crl_verify': {'type': ['string', 'null']},
            'keepalive_ping_interval': {'type': 'integer'},
            'keepalive_peer_down': {'type': 'integer'},
            'user': {'type': 'string'},
            'group': {'type': 'string'},
            'port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'proto': {'type': 'string', 'enum': ['tcp', 'udp']},
            'comp_lzo': {'type': 'boolean'},

            'verb': {
                'type': 'integer',
                'minimum': 0,
                'maximum': 15
            },
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_provider("service.openvpn", OpenVpnProvider)
    plugin.register_provider("service.openvpn.client_config", OpenVPNClientConfigProvider)

    plugin.register_task_handler('service.openvpn.update', OpenVpnConfigureTask)
    plugin.register_task_handler('service.openvpn.gen_key', OpenVPNGenerateKeys)
