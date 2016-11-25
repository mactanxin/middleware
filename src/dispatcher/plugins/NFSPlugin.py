#
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
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, ValidationException, TaskDescription
from debug import AttachFile
from utils import is_port_open


logger = logging.getLogger('NFSPlugin')


@description('Provides info about NFS service configuration')
class NFSProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('service-nfs'))
    def get_config(self):
        return ConfigNode('service.nfs', self.configstore).__getstate__()


@private
@description('Configure NFS service')
@accepts(h.ref('service-nfs'))
class NFSConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring NFS service'

    def describe(self, nfs):
        return TaskDescription('Configuring NFS service')

    def verify(self, nfs):
        return ['system']

    def run(self, nfs):
        config = self.dispatcher.call_sync('service.query', [('name', '=', 'nfs')], {'single': True})['config']
        for n in ('mountd_port', 'rpcstatd_port', 'rpclockd_port'):
            port = nfs.get(n)
            if port and port != config[n] and is_port_open(port):
                raise TaskException(errno.EBUSY, 'Port number : {0} is already opened'.format(port))

        try:
            node = ConfigNode('service.nfs', self.configstore)
            node.update(nfs)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
            self.dispatcher.call_sync('etcd.generation.generate_group', 'nfs')
            self.dispatcher.dispatch_event('service.nfs.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure NFS: {0}'.format(str(e))
            )

        return 'RESTART'


def collect_debug(dispatcher):
    yield AttachFile('exports', '/etc/exports')
    yield AttachFile('zfs-exports', '/etc/zfs/exports')


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('service-nfs', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['service-nfs']},
            'enable': {'type': 'boolean'},
            'servers': {
                'type': 'integer',
                'minimum': 1,
            },
            'udp': {'type': 'boolean'},
            'nonroot': {'type': 'boolean'},
            'v4': {'type': 'boolean'},
            'v4_kerberos': {'type': 'boolean'},
            'bind_addresses': {
                'type': ['array', 'null'],
                'items': {'type': 'string'},
            },
            'mountd_port': {'type': ['integer', 'null']},
            'rpcstatd_port': {'type': ['integer', 'null']},
            'rpclockd_port': {'type': ['integer', 'null']},
        },
        'additionalProperties': False,
    })

    # Register providers
    plugin.register_provider("service.nfs", NFSProvider)

    # Register tasks
    plugin.register_task_handler("service.nfs.update", NFSConfigureTask)

    # Register debug hook
    plugin.register_debug_hook(collect_debug)
