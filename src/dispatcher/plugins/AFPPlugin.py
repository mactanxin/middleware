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
from pathlib import PosixPath

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, TaskDescription
from debug import AttachFile


logger = logging.getLogger('AFPPlugin')


@description('Provides info about AFP service configuration')
class AFPProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceAfp'))
    def get_config(self):
        return ConfigNode('service.afp', self.configstore).__getstate__()


@private
@description('Configure AFP service')
@accepts(h.ref('ServiceAfp'))
class AFPConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring AFP service'

    def describe(self, share):
        return TaskDescription('Configuring AFP service')

    def verify(self, afp):
        return ['system']

    def run(self, afp):
        paths = [PosixPath(afp.get(y)) if afp.get(y) else None for y in ('dbpath', 'homedir_path')]
        for p in paths:
            if p and not p.exists():
                raise TaskException(errno.ENOENT, 'Path : {0} does not exist'.format(p.as_posix()))
            if p and not p.is_dir():
                raise TaskException(errno.ENOTDIR, 'Path : {0} is not a directory'.format(p.as_posix()))

        if afp.get('guest_user'):
            if not self.dispatcher.call_sync('user.query', [('username', '=', afp['guest_user'])], {'single': True}):
                raise TaskException(errno.EINVAL, 'User: {0} does not exist'.format(afp['guest_user']))

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
    plugin.register_schema_definition('ServiceAfp', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceAfp']},
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

    plugin.register_provider("service.afp", AFPProvider)
    plugin.register_task_handler("service.afp.update", AFPConfigureTask)
    plugin.register_debug_hook(collect_debug)
