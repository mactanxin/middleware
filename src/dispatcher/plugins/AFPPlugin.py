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
import os

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, ValidationException, TaskDescription
from debug import AttachFile


logger = logging.getLogger('AFPPlugin')


@description('Provides info about AFP service configuration')
class AFPProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('service-afp'))
    def get_config(self):
        return ConfigNode('service.afp', self.configstore).__getstate__()


@private
@description('Configure AFP service')
@accepts(h.ref('service-afp'))
class AFPConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring AFP service'

    def describe(self, share):
        return TaskDescription('Configuring AFP service')

    def verify(self, afp):

        errors = ValidationException()
        dbpath = afp.get('dbpath')
        if dbpath:
            if not os.path.exists(dbpath):
                errors.add((0, 'dbpath'), 'Path does not exist', code=errno.ENOENT)
            elif not os.path.isdir(dbpath):
                errors.add((0, 'dbpath'), 'Path is not a directory')

        if errors:
            raise errors

        return ['system']

    def run(self, afp):
        try:
            node = ConfigNode('service.afp', self.configstore)
            node.update(afp)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
            self.dispatcher.call_sync('etcd.generation.generate_group', 'afp')
            self.dispatcher.dispatch_event('service.afp.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure AFP: {0}'.format(str(e))
            )

        return 'RELOAD'


def collect_debug(dispatcher):
    yield AttachFile('afp.conf', '/usr/local/etc/afp.conf')


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('service-afp', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['service-afp']},
            'enable': {'type': 'boolean'},
            'guest_enable': {'type': 'boolean'},
            'guest_user': {'type': 'string'},
            'bind_addresses': {
                'type': ['array', 'null'],
                'items': {'type': 'string'},
            },
            'connections_limit': {'type': 'integer'},
            'homedir_enable': {'type': 'boolean'},
            'homedir_path': {'type': ['string', 'null']},
            'homedir_name': {'type': ['string', 'null']},
            'dbpath': {'type': ['string', 'null']},
            'auxiliary': {'type': ['string', 'null']},

        },
        'additionalProperties': False,
    })

    # Register providers
    plugin.register_provider("service.afp", AFPProvider)

    # Register tasks
    plugin.register_task_handler("service.afp.update", AFPConfigureTask)
