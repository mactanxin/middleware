#+
# Copyright 2014 iXsystems, Inc.
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
from task import Task, Provider, TaskException, VerifyException, TaskDescription, TaskWarning
from freenas.dispatcher.rpc import description, accepts, private
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize, query as q


logger = logging.getLogger(__name__)


@description("Provides info about configured NFS shares")
class NFSSharesProvider(Provider):
    @private
    @accepts(str)
    def get_connected_clients(self, share_id=None):
        share = self.datastore.get_one('shares', ('type', '=', 'nfs'), ('id', '=', share_id))
        result = []
        f = open('/var/db/mountdtab')
        for line in f:
            host, path = line.split()
            if share['target_path'] in path:
                result.append({
                    'host': host,
                    'share': share_id,
                    'user': None,
                    'connected_at': None
                })

        f.close()
        return result


@private
@accepts(h.ref('Share'))
@description("Adds new NFS share")
class CreateNFSShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating NFS share"

    def describe(self, share):
        return TaskDescription("Creating NFS share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        properties = share['properties']
        if (properties.get('maproot_user') or properties.get('maproot_group')) and \
           (properties.get('mapall_user') or properties.get('mapall_group')):
            raise VerifyException(errno.EINVAL, 'Cannot set maproot and mapall properties simultaneously')

        if share['target_type'] != 'DATASET' and properties.get('alldirs'):
            raise VerifyException(errno.EINVAL, 'alldirs can be only used with dataset shares')

        return ['service:nfs']

    def run(self, share):
        normalize(share['properties'], {
            'alldirs': False,
            'read_only': False,
            'maproot_user': None,
            'maproot_group': None,
            'mapall_user': None,
            'mapall_group': None,
            'hosts': [],
            'security': []
        })

        if share['properties']['security'] and not self.dispatcher.call_sync(
                'service.query', [('name', '=', 'nfs')], {'single': True})['config']['v4']:
            self.add_warning(TaskWarning(
                errno.ENXIO, "NFS security option requires NFSv4 support to be enabled in NFS service settings."))

        id = self.datastore.insert('shares', share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'nfs')
        self.dispatcher.call_sync('service.reload', 'nfs', timeout=60)
        return id


@private
@accepts(str, h.ref('Share'))
@description("Updates existing NFS share")
class UpdateNFSShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating NFS share"

    def describe(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Updating NFS share {name}", name=share.get('name', id) if share else id)

    def verify(self, id, updated_fields):
        if 'properties' in updated_fields:
            properties = updated_fields['properties']
            if (properties.get('maproot_user') or properties.get('maproot_group')) and \
               (properties.get('mapall_user') or properties.get('mapall_group')):
                raise VerifyException(errno.EINVAL, 'Cannot set maproot and mapall properties simultaneously')

        return ['service:nfs']

    def run(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        share.update(updated_fields)

        if share['target_type'] != 'DATASET' and q.get(share, 'properties.alldirs'):
            raise TaskException(errno.EINVAL, 'alldirs can be only used with dataset shares')

        if share['properties']['security'] and not self.dispatcher.call_sync(
                'service.query', [('name', '=', 'nfs')], {'single': True})['config']['v4']:
            self.add_warning(TaskWarning(
                errno.ENXIO, "NFS security option requires NFSv4 support to be enabled in NFS service settings."))

        self.datastore.update('shares', id, share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'nfs')
        self.dispatcher.call_sync('service.reload', 'nfs', timeout=60)
        self.dispatcher.dispatch_event('share.nfs.changed', {
            'operation': 'update',
            'ids': [id]
        })


@private
@accepts(str)
@description("Removes NFS share")
class DeleteNFSShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting NFS share"

    def describe(self, id):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Deleting NFS share {name}", name=share.get('name', id) if share else id)

    def verify(self, id):
        return ['service:nfs']

    def run(self, id):
        self.datastore.delete('shares', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'nfs')
        self.dispatcher.call_sync('service.reload', 'nfs', timeout=60)
        self.dispatcher.dispatch_event('share.nfs.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@private
@accepts(h.ref('Share'))
@description("Imports existing NFS share")
class ImportNFSShareTask(CreateNFSShareTask):
    @classmethod
    def early_describe(cls):
        return "Importing NFS share"

    def describe(self, share):
        return TaskDescription("Importing NFS share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        properties = share['properties']
        if (properties.get('maproot_user') or properties.get('maproot_group')) and \
           (properties.get('mapall_user') or properties.get('mapall_group')):
            raise VerifyException(errno.EINVAL, 'Cannot set maproot and mapall properties simultaneously')

        return super(ImportNFSShareTask, self).verify(share)

    def run(self, share):
        return super(ImportNFSShareTask, self).run(share)


@private
@description('Terminates NFS connection')
class TerminateNFSConnectionTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Terminating NFS connection'

    def describe(self, address):
        return TaskDescription('Terminating NFS connection with {name}', name=address)

    def verify(self, address):
        return []

    def run(self, address):
        raise TaskException(errno.ENXIO, 'Not supported')


def _metadata():
    return {
        'type': 'sharing',
        'subtype': 'FILE',
        'perm_type': 'PERM',
        'method': 'nfs'
    }


def _depends():
    return ['ZfsPlugin', 'SharingPlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('ShareNfs', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['ShareNfs']},
            'alldirs': {'type': 'boolean'},
            'read_only': {'type': 'boolean'},
            'maproot_user': {'type': ['string', 'null']},
            'maproot_group': {'type': ['string', 'null']},
            'mapall_user': {'type': ['string', 'null']},
            'mapall_group': {'type': ['string', 'null']},
            'hosts': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'security': {
                'type': 'array',
                'items': {'$ref': 'ShareNfsSecurityItems'}
            }
        }
    })

    plugin.register_schema_definition('ShareNfsSecurityItems', {
        'type': 'string',
        'enum': ['sys', 'krb5', 'krb5i', 'krb5p']
    })

    plugin.register_task_handler("share.nfs.create", CreateNFSShareTask)
    plugin.register_task_handler("share.nfs.update", UpdateNFSShareTask)
    plugin.register_task_handler("share.nfs.delete", DeleteNFSShareTask)
    plugin.register_task_handler("share.nfs.import", ImportNFSShareTask)
    plugin.register_task_handler("share.nfs.terminate_connection", TerminateNFSConnectionTask)
    plugin.register_provider("share.nfs", NFSSharesProvider)
    plugin.register_event_type('share.nfs.changed')
