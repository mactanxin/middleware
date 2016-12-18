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

import os
from task import Task, Provider
from freenas.dispatcher.rpc import private, accepts, returns, generator


class VolumeDatastoreProvider(Provider):
    @private
    @generator
    def discover(self):
        for vol in self.dispatcher.call_sync('volume.query'):
            yield {
                'id': vol['id'],
                'name': vol['id'],
                'type': 'volume'
            }

    @private
    @accepts(str, str)
    def get_filesystem_path(self, datastore_id, datastore_path):
        return self.dispatcher.call_sync('volume.get_dataset_path', os.path.join(datastore_id, datastore_path))

    @private
    @accepts(str)
    def get_resources(self, datastore_id):
        return ['zpool:{0}'.format(datastore_id)]

    @private
    @accepts(str, str)
    def directory_exists(self, datastore_id, datastore_path):
        path = os.path.join(datastore_id, datastore_path)
        return self.dispatcher.call_sync('volume.dataset.query', [('id', '=', path)], {'single': True}) is not None


class VolumeDirectoryCreateTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        return self.run_subtask_sync('volume.dataset.create', {
            'volume': id,
            'id': os.path.join(id, path)
        })


class VolumeDirectoryDeleteTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        return self.run_subtask_sync('volume.dataset.delete', os.path.join(id, path))


class VolumeBlockDeviceCreateTask(Task):
    def verify(self, id, path, size):
        return []

    def run(self, id, path, size):
        return self.run_subtask_sync('volume.dataset.create', {
            'volume': id,
            'id': os.path.join(id, path),
            'type': 'VOLUME',
            'volsize': size
        })


class VolumeBlockDeviceDeleteTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path, size):
        return self.run_subtask_sync('volume.dataset.delete', os.path.join(id, path))


def _metadata():
    return {
        'type': 'datastore',
        'driver': 'volume',
        'block_devices': True,
        'clones': True,
        'snapshots': True
    }


def _init(dispatcher, plugin):
    plugin.register_provider('vm.datastore.volume', VolumeDatastoreProvider)
    plugin.register_task_handler('vm.datastore.volume.create_directory', VolumeDirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.volume.delete_directory', VolumeDirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.volume.create_block_device', VolumeBlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.volume.delete_block_device', VolumeBlockDeviceCreateTask)

