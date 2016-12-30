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
import errno
from task import ProgressTask, Provider, TaskDescription, TaskException
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.dispatcher.rpc import private, accepts, returns, generator, description
from freenas.utils import query as q


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
            'Cloning {name} to {new_name}',
            name=os.path.join(id, path),
            new_name=os.path.join(id, new_path)
        )

    def verify(self, id, path, new_path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path, new_path):
        if '@' in path:
            full_path = os.path.join(id, path)
            dataset, vm_snap_id = full_path.split('@', 1)
            snapshot_id = self.dispatcher.call_sync(
                'volume.snapshot.query',
                [('dataset', '=', dataset), ('metadata.org\.freenas:vm_snapshot', '=', vm_snap_id)],
                {'single': True, 'select': 'id'}
            )

            if not snapshot_id:
                raise TaskException(errno.ENOENT, 'Snapshot {0} not found'.format(path))

        else:
            dataset = os.path.join(id, path)
            snap_cnt = self.dispatcher.call_sync(
                'volume.snapshot.query',
                [('id', '~', '^{0}@vm-clone-'.format(dataset))],
                {'count': True}
            )
            snapshot_id = '{0}@vm-clone-{1}'.format(dataset, snap_cnt)

            self.run_subtask_sync_with_progress(
                'volume.snapshot.create',
                {
                    'id': snapshot_id,
                    'replicable': False,
                }
            )

        return self.run_subtask_sync_with_progress('volume.snapshot.clone', snapshot_id, os.path.join(id, new_path))


@accepts(str, str)
@description('Creates a snapshot of a dataset or a ZVOL representing a block device or a directory')
class VolumeSnapshotCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a dataset snapshot'

    def describe(self, id, path):
        snapshot = os.path.join(id, path)
        return TaskDescription(
            'Creating the dataset {name} snapshot under {new_name}',
            name=snapshot.split('@', 1)[0],
            new_name=snapshot
        )

    def verify(self, id, path):
        return self.dispatcher.call_sync('vm.datastore.volume.get_resources', id)

    def run(self, id, path):
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


@accepts(str, str)
@description('Does a rollback of a dataset or a ZVOL representing a block device or a directory to a selected snapshot')
class VolumeSnapshotRollbackTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Doing a rollback on a dataset'

    def describe(self, id, path):
        snapshot = os.path.join(id, path)
        return TaskDescription(
            'Doing a rollback to the {snapshot} snapshot on the dataset {name}',
            name=snapshot.split('@', 1)[0],
            snapshot=snapshot
        )

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
    plugin.register_task_handler('vm.datastore.volume.directory.create', VolumeDirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.volume.directory.delete', VolumeDirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.volume.directory.rename', VolumeDirectoryRenameTask)
    plugin.register_task_handler('vm.datastore.volume.directory.clone', VolumeCloneTask)
    plugin.register_task_handler('vm.datastore.volume.directory.snapshot.create', VolumeSnapshotCreateTask)
    plugin.register_task_handler('vm.datastore.volume.directory.snapshot.delete', VolumeSnapshotDeleteTask)
    plugin.register_task_handler('vm.datastore.volume.directory.snapshot.rollback', VolumeSnapshotRollbackTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.create', VolumeBlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.delete', VolumeBlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.rename', VolumeBlockDeviceRenameTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.resize', VolumeBlockDeviceResizeTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.clone', VolumeCloneTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.snapshot.create', VolumeSnapshotCreateTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.snapshot.delete', VolumeSnapshotDeleteTask)
    plugin.register_task_handler('vm.datastore.volume.block_device.snapshot.rollback', VolumeSnapshotRollbackTask)

