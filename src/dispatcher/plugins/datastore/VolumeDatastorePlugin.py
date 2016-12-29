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
from task import ProgressTask, Provider, TaskDescription
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.dispatcher.rpc import private, accepts, returns, generator, description


@description('Provides information about ZFS VM datastores')
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
    @returns(str)
    @description('Converts dataset path to local filesystem path')
    def get_filesystem_path(self, datastore_id, datastore_path):
        return self.dispatcher.call_sync('volume.resolve_path', datastore_id, datastore_path)

    @private
    @accepts(str)
    @returns(h.array(str))
    @description('Returns list of resources which have to be locked to safely perform VM datastore operations')
    def get_resources(self, datastore_id):
        return ['zpool:{0}'.format(datastore_id)]

    @private
    @accepts(str, str)
    @returns(bool)
    @description('Checks for existence of dataset representing a VM datastore\'s directory')
    def directory_exists(self, datastore_id, datastore_path):
        path = os.path.join(datastore_id, datastore_path)
        return self.dispatcher.call_sync('volume.dataset.query', [('id', '=', path)], {'single': True}) is not None

    @private
    @generator
    @accepts(str, str)
    @description('Returns a list of snapshots on a given VM datastore path')
    def get_snapshots(self, datastore_id, path):
        return


@accepts(str, str)
@description('Creates a dataset representing a VM datastore\'s directory')
class VolumeDirectoryCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a dataset'

    def describe(self, id, path):
        return TaskDescription('Creating the dataset {name}', name=os.path.join(id, path))

    def verify(self, id, path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path):
        return self.run_subtask_sync_with_progress('volume.dataset.create', {
            'volume': id,
            'id': os.path.join(id, path)
        })


@accepts(str, str)
@description('Deletes a dataset representing a VM datastore\'s directory')
class VolumeDirectoryDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a dataset'

    def describe(self, id, path):
        return TaskDescription('Deleting the dataset {name}', name=os.path.join(id, path))

    def verify(self, id, path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path):
        return self.run_subtask_sync_with_progress('volume.dataset.delete', os.path.join(id, path))


@accepts(str, str, str)
@description('Renames a dataset representing a VM datastore\'s directory')
class VolumeDirectoryRenameTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Renaming a dataset'

    def describe(self, id, old_path, new_path):
        return TaskDescription(
            'Renaming the dataset {name} to {new_name}',
            name=os.path.join(id, old_path),
            new_name=os.path.join(id, new_path)
        )

    def verify(self, id, old_path, new_path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, old_path, new_path):
        dataset_id = os.path.join(id, old_path)
        return self.run_subtask_sync_with_progress('volume.dataset.update', dataset_id, {
            'id': os.path.join(id, new_path)
        })


@accepts(str, str, int)
@description('Creates a ZVOL representing a VM datastore\'s block device')
class VolumeBlockDeviceCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a ZVOL'

    def describe(self, id, path, size):
        return TaskDescription('Creating the ZVOL {name}', name=os.path.join(id, path))

    def verify(self, id, path, size):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path, size):
        return self.run_subtask_sync_with_progress('volume.dataset.create', {
            'volume': id,
            'id': os.path.join(id, path),
            'type': 'VOLUME',
            'volsize': size
        })


@accepts(str, str)
@description('Deletes a ZVOL representing a VM datastore\'s block device')
class VolumeBlockDeviceDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a ZVOL'

    def describe(self, id, path):
        return TaskDescription('Deleting the ZVOL {name}', name=os.path.join(id, path))

    def verify(self, id, path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path):
        return self.run_subtask_sync_with_progress('volume.dataset.delete', os.path.join(id, path))


@accepts(str, str, str)
@description('Renames a ZVOL representing a VM datastore\'s block device')
class VolumeBlockDeviceRenameTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Renaming a ZVOL'

    def describe(self, id, old_path, new_path):
        return TaskDescription(
            'Renaming the ZVOL {name} to {new_name}',
            name=os.path.join(id, old_path),
            new_name=os.path.join(id, new_path)
        )

    def verify(self, id, old_path, new_path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, old_path, new_path):
        return self.run_subtask_sync_with_progress('volume.dataset.delete', os.path.join(id, old_path), {
            'id': os.path.join(id, new_path)
        })


@accepts(str, str, int)
@description('Resizes a ZVOL representing a VM datastore\'s block device')
class VolumeBlockDeviceResizeTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Resizing a ZVOL'

    def describe(self, id, path, new_size):
        return TaskDescription('Resizing the ZVOL {name}', name=os.path.join(id, path))

    def verify(self, id, path, new_size):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path, new_size):
        return self.run_subtask_sync_with_progress('volume.dataset.update', os.path.join(id, path), {
            'volsize': new_size
        })


@accepts(str, str, str)
@description('Clones a dataset or a ZVOL representing a block device or a directory')
class VolumeCloneTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Cloning a dataset'

    def describe(self, id, path, new_path):
        return TaskDescription(
            'Cloning the dataset {name} to {new_name}',
            name=os.path.join(id, path),
            new_name=os.path.join(id, new_path)
        )

    def verify(self, id, path, new_path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path, new_path):
        pass


@accepts(str, str, str)
@description('Creates a snapshot of a dataset or a ZVOL representing a block device or a directory')
class VolumeSnapshotCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a dataset snapshot'

    def describe(self, id, path, new_path):
        return TaskDescription(
            'Creating the dataset {name} snapshot under {new_name}',
            name=os.path.join(id, path),
            new_name=os.path.join(id, new_path)
        )

    def verify(self, id, path, new_path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path, new_path):
        pass


@accepts(str, str)
@description('Deletes a snapshot of a dataset or a ZVOL representing a block device or a directory')
class VolumeSnapshotDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a dataset snapshot'

    def describe(self, id, path):
        return TaskDescription('Deleting the dataset snapshot {name}', name=os.path.join(id, path))

    def verify(self, id, path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path):
        pass


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
    plugin.register_task_handler('vm.datastore.volume.rename_directory', VolumeDirectoryRenameTask)
    plugin.register_task_handler('vm.datastore.volume.create_block_device', VolumeBlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.volume.delete_block_device', VolumeBlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.volume.rename_block_device', VolumeBlockDeviceRenameTask)
    plugin.register_task_handler('vm.datastore.volume.resize_block_device', VolumeBlockDeviceResizeTask)
