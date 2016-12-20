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
from task import Task, Provider, TaskException, TaskDescription
from freenas.dispatcher.rpc import description, accepts, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize


@description('Provides information about simulated disks')
class FakeDisksProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('simulator.disks', *(filter or []), **(params or {}))


@description("Creates a Simulated Fake Disk with the parameters provided")
@accepts(
    h.all_of(
        h.ref('simulator-disk'),
        h.required('id')
    )
)
class CreateFakeDisk(Task):
    @classmethod
    def early_describe(cls):
        return "Creating simulated disk"

    def describe(self, disk):
        return TaskDescription("Creating simulated disk {name}", name=disk.get('path', '') if disk else '')

    def verify(self, disk):
        return ['system-dataset']

    def run(self, disk):
        defpath = os.path.join(self.dispatcher.call_sync('system_dataset.request_directory', 'simulator'), disk['id'])
        normalize(disk, {
            'vendor': 'FreeNAS',
            'path': defpath,
            'model': 'Virtual Disk',
            'serial': self.dispatcher.call_sync('share.iscsi.generate_serial'),
            'block_size': 512,
            'rpm': '7200',
            'online': True
        })

        disk['naa'] = self.dispatcher.call_sync('share.iscsi.generate_naa')

        if not os.path.exists(disk['path']):
            with open(disk['path'], 'w') as f:
                f.truncate(disk['mediasize'])

        self.datastore.insert('simulator.disks', disk)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')


@description("Configures the given Simulated Disk ID with the specified parameters")
@accepts(
    str,
    h.all_of(
        h.ref('simulator-disk'),
        h.no(h.required('id'))
    )
)
class ConfigureFakeDisk(Task):
    @classmethod
    def early_describe(cls):
        return "Updating simulated disk"

    def describe(self, id, updated_params):
        disk = self.datastore.get_by_id('simulator.disks', id)
        return TaskDescription("Updating simulated disk {name}", name=disk.get('path', id) if disk else id)

    def verify(self, id, updated_params):
        return ['system-dataset']

    def run(self, id, updated_params):
        if not self.datastore.exists('simulator.disks', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Disk {0} not found'.format(id))

        disk = self.datastore.get_by_id('simulator.disks', id)
        disk.update(updated_params)
        self.datastore.update('simulator.disks', id, disk)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')


@description("Deletes the Simulated Fake Disk identified with the ID provided")
@accepts(str)
class DeleteFakeDisk(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting simulated disk"

    def describe(self, id):
        disk = self.datastore.get_by_id('simulator.disks', id)
        return TaskDescription("Deleting simulated disk {name}", name=disk.get('path', id) if disk else id)

    def verify(self, id):
        return ['system-dataset']

    def run(self, id):
        if not self.datastore.exists('simulator.disks', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Disk {0} not found'.format(id))

        self.datastore.delete('simulator.disks', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')


def _depends():
    return ['SystemDatasetPlugin']


def _init(dispatcher, plugin):

    plugin.register_schema_definition('simulator-disk', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'path': {'type': 'string'},
            'mediasize': {'type': 'integer'},
            'vendor': {'type': 'string'},
            'model': {'type': 'string'},
            'serial': {'type': 'string'},
            'block_size': {'type': 'integer'},
            'online': {'type': 'boolean'},
            'rpm': {'$ref': 'simulator-disk-rpm'}
        }
    })

    plugin.register_schema_definition('simulator-disk-rpm', {
        'type': 'string',
        'enum': ['UNKNOWN', 'SSD', '5400', '7200', '10000', '15000']
    })

    dispatcher.call_sync('system_dataset.request_directory', 'simulator')

    plugin.register_provider('simulator.disk', FakeDisksProvider)
    plugin.register_task_handler('simulator.disk.create', CreateFakeDisk)
    plugin.register_task_handler('simulator.disk.update', ConfigureFakeDisk)
    plugin.register_task_handler('simulator.disk.delete', DeleteFakeDisk)