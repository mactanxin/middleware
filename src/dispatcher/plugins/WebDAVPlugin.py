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
from task import Task, Provider, TaskException, TaskDescription
from utils import is_port_open

logger = logging.getLogger('WebDAVPlugin')


@description('Provides info about WebDAV service configuration')
class WebDAVProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceWebdav'))
    def get_config(self):
        return ConfigNode('service.webdav', self.configstore).__getstate__()


@private
@description('Configure WebDAV service')
@accepts(h.ref('ServiceWebdav'))
class WebDAVConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring WebDAV service'

    def describe(self, webdav):
        return TaskDescription('Configuring WebDAV service')

    def verify(self, webdav):
        return ['system']

    def run(self, webdav):
        node = ConfigNode('service.webdav', self.configstore).__getstate__()

        for p in ('http_port', 'https_port'):
            port = webdav.get(p)
            if port and port != node[p] and is_port_open(port):
                raise TaskException(errno.EBUSY, 'Port number : {0} is already in use'.format(port))

        node.update(webdav)

        if node['http_port'] == node['https_port']:
            raise TaskException(errno.EINVAL, 'HTTP and HTTPS ports cannot be the same')

        if 'HTTPS' in node['protocol'] and not node['certificate']:
            raise TaskException(errno.EINVAL, 'SSL protocol specified without choosing a certificate')

        if node['certificate'] and not self.dispatcher.call_sync(
            'crypto.certificate.query', [('name', '=', node['certificate'])], {'count': True}
        ):
                raise TaskException(errno.ENOENT, 'SSL Certificate not found.')

        try:
            node = ConfigNode('service.webdav', self.configstore)
            node.update(webdav)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
            self.dispatcher.call_sync('etcd.generation.generate_group', 'webdav')
            self.dispatcher.dispatch_event('service.webdav.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure WebDAV: {0}'.format(str(e))
            )

        return 'RESTART'


def _depends():
    return ['CryptoPlugin', 'ServiceManagePlugin']


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('ServiceWebdav', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceWebdav']},
            'enable': {'type': 'boolean'},
            'protocol': {
                'type': ['array'],
                'items': {'$ref': 'ServiceWebdavProtocolItems'},
            },
            'http_port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'https_port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'password': {'type': 'string'},
            'authentication': {'$ref': 'ServiceWebdavAuthentication'},
            'certificate': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ServiceWebdavProtocolItems', {
        'type': 'string',
        'enum': ['HTTP', 'HTTPS']
    })

    plugin.register_schema_definition('ServiceWebdavAuthentication', {
        'type': 'string',
        'enum': ['BASIC', 'DIGEST']
    })

    # Register providers
    plugin.register_provider("service.webdav", WebDAVProvider)

    # Register tasks
    plugin.register_task_handler("service.webdav.update", WebDAVConfigureTask)
