#
# Copyright 2016 iXsystems, Inc.
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

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskDescription


@description('Provides info about Consul service configuration')
class ConsulProvider(Provider):
    @returns(h.ref('ServiceConsul'))
    @private
    def get_config(self):
        return ConfigNode('service.consul', self.configstore).__getstate__()


@description('Configures Consul service')
@accepts(h.ref('ServiceConsul'))
@private
class ConsulConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring Consul service'

    def describe(self, updated_fields):
        return TaskDescription('Configuring Consul service')

    def verify(self, updated_fields):
        return ['system']

    def run(self, updated_fields):
        node = ConfigNode('service.consul', self.configstore).__getstate__()
        node.update(updated_fields)
        return 'RELOAD'


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('ServiceConsul', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['ServiceConsul']},
            'bind_address': {'type': ['string', 'null']},
            'enable': {'type': 'boolean'},
            'datacenter': {'type': 'string'},
            'node_name': {'type': ['string', 'null']},
            'server': {'type': 'boolean'},
            'start_join': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'start_join_wan': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'retry_join': {'type': 'boolean'},
            'encryption_key': {'type': ['string', 'null']}
        }
    })

    # Register providers
    plugin.register_provider("service.consul", ConsulProvider)

    # Register tasks
    plugin.register_task_handler("service.consul.update", ConsulConfigureTask)
