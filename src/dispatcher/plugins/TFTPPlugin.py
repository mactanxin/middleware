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
from freenas.utils.permissions import get_unix_permissions, get_integer

logger = logging.getLogger('TFTPPlugin')


@description('Provides info about TFTP service configuration')
class TFTPProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceTftpd'))
    def get_config(self):
        config = ConfigNode('service.tftpd', self.configstore).__getstate__()
        config['umask'] = get_unix_permissions(config['umask'])
        return config


@private
@description('Configure TFTP service')
@accepts(h.ref('ServiceTftpd'))
class TFTPConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring TFTP service'

    def describe(self, tftp):
        return TaskDescription('Configuring TFTP service')

    def verify(self, tftp):
        errors = []

        if errors:
            raise ValidationException(errors)

        return ['system']

    def run(self, tftp):
        try:
            node = ConfigNode('service.tftpd', self.configstore)
            tftp['umask'] = get_integer(tftp['umask'])
            node.update(tftp)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
            self.dispatcher.dispatch_event('service.tftpd.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure TFTP: {0}'.format(str(e))
            )

        return 'RESTART'


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):

    # Register schemas
    plugin.register_schema_definition('ServiceTftpd', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceTftpd']},
            'enable': {'type': 'boolean'},
            'port': {'type': 'integer'},
            'path': {'type': 'string'},
            'allow_new_files': {'type': 'boolean'},
            'username': {'type': 'string'},
            'umask': {'$ref': 'UnixPermissions'},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    # Register providers
    plugin.register_provider("service.tftpd", TFTPProvider)

    # Register tasks
    plugin.register_task_handler("service.tftpd.update", TFTPConfigureTask)
