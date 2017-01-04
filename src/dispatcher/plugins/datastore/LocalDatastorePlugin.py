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
import shutil
import errno
import contextlib
from task import Task, TaskDescription, Provider
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.dispatcher.rpc import RpcException, private, accepts, returns, generator, description
from freenas.utils import query as q


@description('Provides information about local VM datastores')
class LocalDatastoreProvider(Provider):
    @private
    @generator
    def discover(self):
        return

    @private
    @accepts(str, str)
    @returns(str)
    @description('Converts VM datastore path to local filesystem path')
    def get_filesystem_path(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'local':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.join(q.get(ds, 'properties.path'), datastore_path)

    @private
    @accepts(str, str)
    @returns(bool)
    @description('Checks for directory existence in local VM datastore')
    def directory_exists(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'local':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.exists(os.path.join(q.get(ds, 'properties.path'), datastore_path))

    @private
    @accepts(str)
    @returns(h.array(str))
    @description('Returns list of resources which have to be locked to safely perform VM datastore operations')
    def get_resources(self, datastore_id):
        return ['system']

    @private
    @generator
    @accepts(str, str)
    @description('Returns a list of snapshots on a given VM datastore path')
    def get_snapshots(self, datastore_id, path):
        return


@accepts(str, str)
@description('Creates a directory on a local filesystem')
class LocalDirectoryCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating a directory'

    def describe(self, id, path):
        return TaskDescription('Creating the directory {name}', name=path)

    def verify(self, id, path):
        return ['system']

    def run(self, id, path):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        os.mkdir(path)


@accepts(str, str)
@description('Deletes a directory on a local filesystem')
class LocalDirectoryDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting a directory'

    def describe(self, id, path):
        return TaskDescription('Deleting the directory {name}', name=path)

    def verify(self, id, path):
        return ['system']

    def run(self, id, path):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        shutil.rmtree(path, ignore_errors=True)


@accepts(str, str, str)
@description('Renames a directory on a local filesystem')
class LocalDirectoryRenameTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Renaming a directory'

    def describe(self, id, old_path, new_path):
        return TaskDescription('Renaming the directory {name} to {new_name}', name=old_path, new_name=new_path)

    def verify(self, id, old_path, new_path):
        return ['system']

    def run(self, id, old_path, new_path):
        old_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, old_path)
        new_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, new_path)
        os.rename(old_path, new_path)


@accepts(str, str, int)
@description('Truncates a block device on a local filesystem')
class LocalBlockDeviceTruncateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Truncating a block device'

    def describe(self, id, path, size):
        return TaskDescription('Truncating a block device {name}', name=path)

    def verify(self, id, path, size):
        return ['system']

    def run(self, id, path, size):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        os.truncate(path, size)


@accepts(str, str)
@description('Deletes a block device from a local filesystem')
class LocalBlockDeviceDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting a block device'

    def describe(self, id, path):
        return TaskDescription('Deleting the block device {name}', name=path)

    def verify(self, id, path):
        return ['system']

    def run(self, id, path):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        with contextlib.suppress(OSError):
            os.remove(path)


@accepts(str, str, str)
@description('Renames a block device on a local filesystem')
class LocalBlockDeviceRenameTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Renaming a block device'

    def describe(self, id, old_path, new_path):
        return TaskDescription('Renaming the block device {name} to {new_name}', name=old_path, new_name=new_path)

    def verify(self, id, old_path, new_path):
        return ['system']

    def run(self, id, old_path, new_path):
        old_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, old_path)
        new_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, new_path)
        os.rename(old_path, new_path)


def _metadata():
    return {
        'type': 'datastore',
        'driver': 'local',
        'clones': False,
        'snapshots': False
    }


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vm-datastore-properties-local', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-datastore-local']},
            'path': {'type': 'string'}
        }
    })

    plugin.register_provider('vm.datastore.local', LocalDatastoreProvider)
    plugin.register_task_handler('vm.datastore.local.directory.create', LocalDirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.local.directory.delete', LocalDirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.local.directory.rename', LocalDirectoryRenameTask)
    plugin.register_task_handler('vm.datastore.local.block_device.create', LocalBlockDeviceTruncateTask)
    plugin.register_task_handler('vm.datastore.local.block_device.delete', LocalBlockDeviceDeleteTask)
    plugin.register_task_handler('vm.datastore.local.block_device.rename', LocalBlockDeviceRenameTask)
    plugin.register_task_handler('vm.datastore.local.block_device.resize', LocalBlockDeviceTruncateTask)
