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
import logging

from datastore.config import ConfigNode
from freenas.dispatcher import Password
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, ValidationException, TaskDescription

logger = logging.getLogger('DynDNSPlugin')

PROVIDERS = {
    'dyndns.org': 'dyndns@dyndns.org',
    'freedns.afraid.org': 'default@freedns.afraid.org',
    'zoneedit.com': 'default@zoneedit.com',
    'no-ip.com': 'default@no-ip.com',
    'easydns.com': 'default@easydns.com',
    '3322.org': 'dyndns@3322.org',
    'sitelutions.com': 'default@sitelutions.com',
    'dnsomatic.com': 'default@dnsomatic.com',
    'he.net': 'ipv6tb@he.net',
    'tzo.com': 'default@tzo.com',
    'dynsip.org': 'default@dynsip.org',
    'dhis.org': 'default@dhis.org',
    'majimoto.net': 'default@majimoto.net',
    'zerigo.com': 'default@zerigo.com',
    'google.com': 'default@domains.google.com',
}


@description('Provides info about DynamicDNS service configuration')
class DynDNSProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceDyndns'))
    def get_config(self):
        state = ConfigNode('service.dyndns', self.configstore).__getstate__()
        state['password'] = Password(state['password'])
        return state

    @accepts()
    @returns(h.object())
    def providers(self):
        return PROVIDERS


@private
@description('Configure DynamicDNS service')
@accepts(h.ref('ServiceDyndns'))
class DynDNSConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring DynamicDNS service'

    def describe(self, dyndns):
        return TaskDescription('Configuring DynamicDNS service')

    def verify(self, dyndns):
        errors = []

        if errors:
            raise ValidationException(errors)

        return ['system']

    def run(self, dyndns):
        try:
            node = ConfigNode('service.dyndns', self.configstore)
            if 'password' in dyndns:
                dyndns['password'] = dyndns['password'].secret

            node.update(dyndns)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'dyndns')
            self.dispatcher.dispatch_event('service.dyndns.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure DynamicDNS: {0}'.format(str(e))
            )

        return 'RELOAD'


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('ServiceDyndns', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceDyndns']},
            'enable': {'type': 'boolean'},
            'provider': {'$ref': 'ServiceDyndnsProvider'},
            'ipserver': {'type': ['string', 'null']},
            'domains': {'type': 'array', 'items': {'type': 'string'}},
            'username': {'type': 'string'},
            'password': {'type': 'password'},
            'update_period': {'type': ['integer', 'null']},
            'force_update_period': {'type': ['integer', 'null']},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ServiceDyndnsProvider', {
        'type': ['string', 'null'],
        'enum': [None] + list(PROVIDERS.values())
    })

    # Register providers
    plugin.register_provider("service.dyndns", DynDNSProvider)

    # Register tasks
    plugin.register_task_handler("service.dyndns.update", DynDNSConfigureTask)
