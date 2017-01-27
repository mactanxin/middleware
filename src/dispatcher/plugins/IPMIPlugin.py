#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
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

import os
import re
import errno
import ipaddress
import logging
import contextlib
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from task import Provider, Task, TaskException, query, TaskDescription
from lib.system import system, SubprocessException
from bsd import kld
from freenas.utils import query as q


RE_ATTRS = re.compile(r'^(?P<key>^.+?)\s+?:\s+?(?P<val>.+?)\r?$', re.M)
IPMI_ATTR_MAP = {
    'IP Address Source': 'dhcp',
    'IP Address': 'address',
    'Subnet Mask': 'netmask',
    'Default Gateway IP': 'gateway',
    '802.1q VLAN ID': 'vlan_id'
}


logger = logging.getLogger('IPMIPlugin')
channels = []


@description('Provides information about IPMI')
class IPMIProvider(Provider):
    @accepts()
    @returns(bool)
    def is_ipmi_loaded(self):
        return os.path.exists('/dev/ipmi0')

    @accepts()
    @returns(h.array(int))
    def channels(self):
        return channels

    @query('Ipmi')
    @generator
    def query(self, filter=None, params=None):
        if not self.is_ipmi_loaded():
            raise RpcException(errno.ENXIO, 'The IPMI device could not be found')

        result = []
        for channel in self.channels():
            try:
                out, err = system('/usr/local/bin/ipmitool', 'lan', 'print', str(channel))
            except SubprocessException as e:
                raise RpcException(errno.EFAULT, 'Cannot receive IPMI configuration: {0}'.format(e.err.strip()))

            raw = {k.strip(): v.strip() for k, v in RE_ATTRS.findall(out)}
            ret = {IPMI_ATTR_MAP[k]: v for k, v in list(raw.items()) if k in IPMI_ATTR_MAP}
            ret['id'] = channel
            ret['vlan_id'] = None if ret.get('vlan_id') == 'Disabled' else ret.get('vlan_id')
            ret['dhcp'] = True if ret.get('dhcp') == 'DHCP Address' else False
            result.append(ret)

        return q.query(result, *(filter or []), stream=True, **(params or {}))


@accepts(int, h.ref('Ipmi'))
@description("Configures IPMI module")
class ConfigureIPMITask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring IPMI module'

    def describe(self, id, updated_params):
        config = self.dispatcher.call_sync('ipmi.query', [('id', '=', id)], {'single': True})
        return TaskDescription('Configuring {name} IPMI module', name=config.get('address', '') if config else '')

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        if not self.dispatcher.call_sync('ipmi.is_ipmi_loaded'):
            raise TaskException(errno.ENXIO, 'No IPMI module loaded')

        if id not in self.dispatcher.call_sync('ipmi.channels'):
            raise TaskException(errno.ENXIO, 'Invalid channel')

        config = self.dispatcher.call_sync('ipmi.query', [('id', '=', id)], {'single': True})
        config.update(updated_params)
        channel = str(id)

        if updated_params.get('gateway') is None:
            config['gateway'] = '0.0.0.0'

        try:
            if config['dhcp']:
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'ipsrc', 'dhcp')
            else:
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'ipsrc', 'static')
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'ipaddr', config['address'])
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'netmask', cidr_to_netmask(config['netmask']))
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'defgw', 'ipaddr', config['gateway'])

            vlan_id = config['vlan_id'] if config.get('vlan_id') else 'off'
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'vlan', 'id', str(vlan_id))
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'access', 'on')
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'auth', 'USER', 'MD2,MD5')
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'auth', 'OPERATOR', 'MD2,MD5')
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'auth', 'ADMIN', 'MD2,MD5')
            system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'auth', 'CALLBACK', 'MD2,MD5')

            with contextlib.suppress(SubprocessException):
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'arp', 'respond', 'on')

            with contextlib.suppress(SubprocessException):
                system('/usr/local/bin/ipmitool', 'lan', 'set', channel, 'arp', 'generate', 'on')

            if 'password' in updated_params:
                system('/usr/local/bin/ipmitool', 'user', 'set', 'password', '2', updated_params['password'])
                system('/usr/local/bin/ipmitool', 'user', 'enable', '2')

        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot configure IPMI channel {0}: {1}'.format(channel, err.err))


def cidr_to_netmask(cidr):
    iface = ipaddress.ip_interface('0.0.0.0/{0}'.format(cidr))
    return str(iface.netmask)


def _init(dispatcher, plugin):
    plugin.register_schema_definition('Ipmi', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'integer'},
            'password': {
                'type': 'string',
                'maxLength': 20
            },
            'dhcp': {'type': 'boolean'},
            'address': {'$ref': 'Ipv4Address'},
            'netmask': {'type': 'integer'},
            'gateway': {
                'anyOf': [
                    {'$ref': 'Ipv4Address'},
                    {'type': 'null'}
                ]
            },
            'vlan_id': {'type': ['integer', 'null']}
        }
    })

    plugin.register_provider('ipmi', IPMIProvider)
    plugin.register_task_handler('ipmi.update', ConfigureIPMITask)

    # Load ipmi kernel module
    try:
        kld.kldload('/boot/kernel/ipmi.ko')
    except OSError as err:
        if err.errno != errno.EEXIST:
            logger.warning('Cannot load IPMI module: %s', str(err))
            logger.warning('IPMI unavailable')
            return

    # Scan available channels
    for i in range(1, 17):
        try:
            system('/usr/local/bin/ipmitool', 'lan', 'print', str(i))
        except SubprocessException:
            continue

        channels.append(i)
