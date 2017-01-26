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
import errno
import jsonschema
import logging
import re

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, TaskDescription

logger = logging.getLogger('SNMPPlugin')


@description('Provides info about SNMP service configuration')
class SNMPProvider(Provider):
    @accepts()
    @returns(h.ref('ServiceSnmp'))
    def get_config(self):
        return ConfigNode('service.snmp', self.configstore).__getstate__()


@private
@description('Configure SNMP service')
@accepts(h.ref('ServiceSnmp'))
class SNMPConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring SNMP service'

    def describe(self, snmp):
        return TaskDescription('Configuring SNMP service')

    def verify(self, snmp):
        return ['system']

    def run(self, snmp):
        node = ConfigNode('service.snmp', self.configstore).__getstate__()
        node.update(snmp)

        if node['contact']:
            if '@' in node['contact']:
                if not jsonschema._format.is_email(node['contact']):
                    raise TaskException(errno.EINVAL, 'Invalid e-mail address')
            elif not re.match(r'^[-_a-zA-Z0-9\s]+$', node['contact']):
                raise TaskException(
                    errno.EINVAL,
                    'Must contain only alphanumeric characters, _, - or a valid e-mail address'
                )

        if not node['community']:
            if not node['v3']:
                raise TaskException(errno.ENOENT, 'This field is required')
        elif not re.match(r'^[-_a-zA-Z0-9\s]+$', node['community']):
            raise TaskException(
                errno.EINVAL,
                'The community must contain only alphanumeric characters, _ or -'
            )

        if node['v3_password'] and len(node['v3_password']) < 8:
            raise TaskException(errno.EINVAL, 'Password must contain at least 8 characters')

        if node['v3_privacy_passphrase'] and len(node['v3_privacy_passphrase']) < 8:
            raise TaskException(errno.EINVAL, 'Passphrase must contain at least 8 characters')

        try:
            node = ConfigNode('service.snmp', self.configstore)
            node.update(snmp)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'snmpd')
            self.dispatcher.dispatch_event('service.snmp.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure SNMP: {0}'.format(str(e))
            )

        return 'RESTART'


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):

    # Register schemas
    plugin.register_schema_definition('ServiceSnmp', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceSnmp']},
            'enable': {'type': 'boolean'},
            'location': {'type': ['string', 'null']},
            'contact': {'type': ['string', 'null']},
            'community': {'type': ['string', 'null']},
            'v3': {'type': 'boolean'},
            'v3_username': {'type': ['string', 'null']},
            'v3_password': {'type': ['string', 'null']},
            'v3_auth_type': {'$ref': 'ServiceSnmpV3authtype'},
            'v3_privacy_protocol': {'$ref': 'ServiceSnmpV3privacyprotocol'},
            'v3_privacy_passphrase': {'type': ['string', 'null']},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ServiceSnmpV3authtype', {
        'type': 'string',
        'enum': ['MD5', 'SHA']
    })

    plugin.register_schema_definition('ServiceSnmpV3privacyprotocol', {
        'type': 'string',
        'enum': ['AES', 'DES']
    })

    # Register providers
    plugin.register_provider("service.snmp", SNMPProvider)

    # Register tasks
    plugin.register_task_handler("service.snmp.update", SNMPConfigureTask)
