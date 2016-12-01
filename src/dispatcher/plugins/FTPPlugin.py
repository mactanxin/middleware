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

import os
import errno
import logging

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from task import Task, Provider, TaskException, ValidationException, TaskDescription
from freenas.utils.permissions import get_unix_permissions, get_integer


logger = logging.getLogger('FTPPlugin')


@description('Provides info about FTP service configuration')
class FTPProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('service-ftp'))
    def get_config(self):
        config = ConfigNode('service.ftp', self.configstore).__getstate__()
        config['filemask'] = get_unix_permissions(config['filemask'])
        config['dirmask'] = get_unix_permissions(config['dirmask'])
        return config


@private
@description('Configure FTP service')
@accepts(h.ref('service-ftp'))
class FTPConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring FTP service'

    def describe(self, ftp):
        return TaskDescription('Configuring FTP service')

    def verify(self, ftp):
        errors = ValidationException()
        node = ConfigNode('service.ftp', self.configstore).__getstate__()
        node.update(ftp)

        pmin = node['passive_ports_min']
        if 'passive_ports_min' in ftp:
            if pmin and (pmin < 1024 or pmin > 65535):
                errors.add((0, 'passive_ports_min'), 'This value must be between 1024 and 65535, inclusive.')

        pmax = node['passive_ports_max']
        if 'passive_ports_max' in ftp:
            if pmax and (pmax < 1024 or pmax > 65535):
                errors.add((0, 'passive_ports_max'), 'This value must be between 1024 and 65535, inclusive.')
            elif pmax and pmin and pmin >= pmax:
                errors.add((0, 'passive_ports_max'),  'This value must be higher than minimum passive port.')

        if node['only_anonymous'] and not node['anonymous_path']:
            errors.add(
                (0, 'anonymous_path'), 'This field is required for anonymous login.'
            )

        if node['tls'] is True and not node['tls_ssl_certificate']:
            errors.add((0, 'tls_ssl_certificate'), 'TLS specified without certificate.')

        if node['tls_ssl_certificate']:
            cert = self.dispatcher.call_sync('crypto.certificate.query', [('id', '=', node['tls_ssl_certificate'])])
            if not cert:
                errors.add((0, 'tls_ssl_certificate'), 'SSL Certificate not found.')

        if node['only_anonymous'] and node['only_local']:
            errors.add(
                (0, 'only_anonymous'), 'only_anonymous and only_local properties cannot be enabled together.'
            )

        if errors:
            raise errors

        return ['system']

    def run(self, ftp):
        if ftp.get('filemask'):
            ftp['filemask'] = get_integer(ftp['filemask'])

        if ftp.get('dirmask'):
            ftp['dirmask'] = get_integer(ftp['dirmask'])

        if ftp.get('anonymous_path'):
            if not os.path.exists(ftp['anonymous_path']):
                raise TaskException(errno.ENOENT,
                    'Directory {0} does not exists'.format(ftp['anonymous_path']))

        try:
            node = ConfigNode('service.ftp', self.configstore)
            node.update(ftp)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'ftp')
            self.dispatcher.dispatch_event('service.ftp.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure FTP: {0}'.format(str(e))
            )

        return 'RESTART'


def _depends():
    return ['CryptoPlugin', 'ServiceManagePlugin']


def _init(dispatcher, plugin):

    # Register schemas
    plugin.register_schema_definition('service-ftp', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['service-ftp']},
            'enable': {'type': 'boolean'},
            'port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'max_clients': {'type': 'integer'},
            'ip_connections': {'type': ['integer', 'null']},
            'login_attempt': {'type': 'integer'},
            'timeout': {'type': 'integer'},
            'root_login': {'type': 'boolean'},
            'anonymous_path': {'type': ['string', 'null']},
            'only_anonymous': {'type': 'boolean'},
            'only_local': {'type': 'boolean'},
            'display_login': {'type': ['string', 'null']},
            'filemask': {'$ref': 'unix-permissions'},
            'dirmask': {'$ref': 'unix-permissions'},
            'fxp': {'type': 'boolean'},
            'resume': {'type': 'boolean'},
            'chroot': {'type': 'boolean'},
            'ident': {'type': 'boolean'},
            'reverse_dns': {'type': 'boolean'},
            'masquerade_address': {'type': ['string', 'null']},
            'passive_ports_min': {'type': ['integer', 'null']},
            'passive_ports_max': {'type': ['integer', 'null']},
            'local_up_bandwidth': {'type': ['integer', 'null']},
            'local_down_bandwidth': {'type': ['integer', 'null']},
            'anon_up_bandwidth': {'type': ['integer', 'null']},
            'anon_down_bandwidth': {'type': ['integer', 'null']},
            'tls': {'type': 'boolean'},
            'tls_policy': {'$ref': 'service-ftp-tlspolicy'},
            'tls_options': {
                'type': 'array',
                'items': {'$ref': 'service-ftp-tlsoptions-items'}
            },
            'tls_ssl_certificate': {'type': ['string', 'null']},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('service-ftp-tlspolicy', {
        'type': 'string',
        'enum': ['ON', 'OFF', 'DATA', '!DATA', 'AUTH', 'CTRL',
                 'CTRL+DATA', 'CTRL+!DATA', 'AUTH+DATA', 'AUTH+!DATA']
    })

    plugin.register_schema_definition('service-ftp-tlsoptions-items', {
        'type': 'string',
        'enum': ['ALLOW_CLIENT_RENEGOTIATIONS', 'ALLOW_DOT_LOGIN', 'ALLOW_PER_USER',
            'COMMON_NAME_REQUIRED', 'ENABLE_DIAGNOSTICS', 'EXPORT_CERTIFICATE_DATA',
            'NO_CERTIFICATE_REQUEST', 'NO_EMPTY_FRAGMENTS', 'NO_SESSION_REUSE_REQUIRED',
            'STANDARD_ENV_VARS', 'DNS_NAME_REQUIRED', 'IP_ADDRESS_REQUIRED']
    })

    # Register providers
    plugin.register_provider("service.ftp", FTPProvider)

    # Register tasks
    plugin.register_task_handler("service.ftp.update", FTPConfigureTask)
